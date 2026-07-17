#include "ft_nmap.h"

unsigned short checksum(void *data, size_t len)
{
    unsigned int    sum;
    unsigned short  *word;

    sum = 0;
    word = data;
    while (len > 1)
    {
        sum += *word++;
        len -= 2;
    }
    if (len == 1)
        sum += *(unsigned char *)word;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (unsigned short)(~sum);
}

static struct in_addr get_source_ip(struct in_addr target_ip)
{
    int                 sockfd;
    struct sockaddr_in  target;
    struct sockaddr_in  source;
    socklen_t           source_len;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1)
        fatal_error(strerror(errno));
    target = get_sockaddr(target_ip, 53);
    if (connect(sockfd, (struct sockaddr *)&target, sizeof(target)) == -1)
        fatal_error(strerror(errno));
    source_len = sizeof(source);
    if (getsockname(sockfd, (struct sockaddr *)&source, &source_len) == -1)
        fatal_error(strerror(errno));
    close(sockfd);
    return source.sin_addr;
}

void fill_ip_header(t_ip_header *ip, struct in_addr source_ip, struct in_addr target_ip, uint16_t total_len, uint8_t protocol)
{
    memset(ip, 0, sizeof(*ip));

    ip->ihl = 5;
    ip->version = 4;
# ifdef __APPLE__
    ip->tot_len = total_len;
# else
    ip->tot_len = htons(total_len);
# endif
    ip->id = htons((unsigned short)getpid());
    ip->ttl = get_option(OPT_TTL)->value;
    ip->protocol = protocol;
    ip->saddr = source_ip.s_addr;
    ip->daddr = target_ip.s_addr;
    ip->check = checksum(ip, sizeof(*ip));
}

static int open_raw_socket(void)
{
    int sockfd;
    int one;

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd == -1)
        fatal_error(strerror(errno));
    one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) == -1)
        fatal_error(strerror(errno));
    return sockfd;
}

static char *get_pcap_device(struct in_addr source_ip)
{
    pcap_if_t       *devices;
    pcap_if_t       *device;
    pcap_addr_t     *address;
    struct in_addr  device_ip;
    char            errbuf[PCAP_ERRBUF_SIZE];
    char            *name;

    if (pcap_findalldevs(&devices, errbuf) == -1)
        fatal_error(errbuf);
    name = NULL;
    device = devices;
    while (device && !name)
    {
        address = device->addresses;
        while (address)
        {
            if (address->addr && address->addr->sa_family == AF_INET)
            {
                device_ip = ((struct sockaddr_in *)address->addr)->sin_addr;
                if (device_ip.s_addr == source_ip.s_addr)
                {
                    name = malloc(strlen(device->name) + 1);
                    if (name)
                        strcpy(name, device->name);
                    break;
                }
            }
            address = address->next;
        }
        device = device->next;
    }
    pcap_freealldevs(devices);
    if (!name)
        fatal_error("Failed to find capture interface");
    return name;
}

static pcap_t *open_pcap(const char *device, uint16_t source_port, struct in_addr target_ip)
{
    pcap_t              *handle;
    char                errbuf[PCAP_ERRBUF_SIZE];
    char                filter[256];
    struct bpf_program  program;

    handle = pcap_open_live(device, 65535, 0, 1, errbuf);
    if (!handle)
        fatal_error(errbuf);
    if (pcap_setnonblock(handle, 1, errbuf) == -1)
        fatal_error(errbuf);
    snprintf(filter, sizeof(filter),
        "((tcp or udp) and src host %s) or "
        "(icmp and icmp[28:2] = %u)",
        to_str(target_ip), source_port);
    if (pcap_compile(handle, &program, filter, 1, 0) == -1)
        fatal_error(pcap_geterr(handle));
    if (pcap_setfilter(handle, &program) == -1)
        fatal_error(pcap_geterr(handle));
    pcap_freecode(&program);
    return handle;
}

const unsigned char *get_ip_packet(const unsigned char *packet, int datalink)
{
    if (datalink == DLT_EN10MB)
        return packet + 14;
# ifdef DLT_LINUX_SLL
    if (datalink == DLT_LINUX_SLL)
        return packet + 16;
# endif
# ifdef DLT_LINUX_SLL2
    if (datalink == DLT_LINUX_SLL2)
        return packet + 20;
# endif
# ifdef DLT_NULL
    if (datalink == DLT_NULL)
        return packet + 4;
# endif
# ifdef DLT_LOOP
    if (datalink == DLT_LOOP)
        return packet + 4;
# endif
    if (datalink == DLT_RAW)
        return packet;
    return NULL;
}

typedef struct s_scan_pool {
    int                 sockfd;
    int                 *ports;
    size_t              port_count;
    size_t              next_port;
    int                 next_scan;
    size_t              task_count;
    size_t              *completed;
    struct in_addr      source_ip;
    t_port_result       *results;
    pthread_mutex_t     lock;
}   t_scan_pool;

typedef struct s_scan_worker {
    t_scan_pool     *pool;
    pcap_t          *pcap;
    uint16_t        source_port;
    int             error;
    struct          in_addr target_ip;
}   t_scan_worker;

static const char *scan_port(int sockfd, pcap_t *pcap,
    struct in_addr source_ip, int port, t_scan scan, uint16_t source_port,
    struct in_addr target_ip)
{
    if (scan == SCAN_UDP)
        return scan_udp_port(sockfd, pcap, source_ip,
            port, source_port, target_ip);
    return scan_tcp_port(sockfd, pcap, source_ip,
        port, scan, source_port, target_ip);
}

static bool get_next_task(t_scan_pool *pool, size_t *port_index, t_scan *scan)
{
    int error;

    error = pthread_mutex_lock(&pool->lock);
    if (error != 0)
        return false;
    while (pool->next_port < pool->port_count)
    {
        if (pool->next_scan == SCAN_COUNT)
        {
            pool->next_port++;
            pool->next_scan = 0;
            continue;
        }
        *scan = pool->next_scan++;
        if (g_opts->scans[*scan])
        {
            *port_index = pool->next_port;
            pthread_mutex_unlock(&pool->lock);
            return true;
        }
    }
    pthread_mutex_unlock(&pool->lock);
    return false;
}

static void *scan_worker(void *arg)
{
    t_scan_worker   *worker;
    t_scan_pool     *pool;
    struct in_addr  target_ip;
    const char      *state;
    size_t          port_index;
    t_scan          scan;

    worker = (t_scan_worker *)arg;
    target_ip = worker->target_ip;

    pool = worker->pool;
    while (g_opts->is_running)
    {
        if (!get_next_task(pool, &port_index, &scan))
            return NULL;
        if (!g_opts->is_running)
            return NULL;
        state = scan_port(pool->sockfd, worker->pcap, pool->source_ip,
            pool->ports[port_index], scan, worker->source_port, target_ip);
        if (!state)
        {
            worker->error = errno;
            if (worker->error == 0)
                worker->error = EIO;
            return NULL;
        }
        if (!g_opts->is_running)
            return NULL;
        pool->results[port_index].states[scan] = state;
        worker->error = pthread_mutex_lock(&pool->lock);
        if (worker->error != 0)
            return NULL;
        pool->completed[port_index]++;
        if (pool->completed[port_index] == pool->task_count)
            pool->results[port_index].is_scanned = true;
        worker->error = pthread_mutex_unlock(&pool->lock);
        if (worker->error != 0)
            return NULL;
    }
    return NULL;
}

static size_t selected_scan_count(void)
{
    size_t  count;
    int     scan;

    count = 0;
    scan = 0;
    while (scan < SCAN_COUNT)
    {
        if (g_opts->scans[scan])
            count++;
        scan++;
    }
    return count;
}

static uint16_t worker_source_port(uint16_t base_port, int worker_index)
{
    // source +1 per port, restart at base if > UINT16_MAX
    return (uint16_t)(((base_port - 1 + worker_index) % UINT16_MAX) + 1);
}

static void run_parallel_scans(int sockfd, struct in_addr source_ip,
    int *ports, size_t port_count, t_port_result *results, int speedup,
    uint16_t source_port, const char *device, struct in_addr target_ip)
{
    pthread_t       threads[MAX_THREADS];
    t_scan_worker   workers[MAX_THREADS];
    t_scan_pool     pool;
    int             worker_count;
    int             created;
    int             error;
    int             result;
    int             i;

    pool.sockfd = sockfd;
    pool.ports = ports;
    pool.port_count = port_count;
    pool.next_port = 0;
    pool.next_scan = 0;
    pool.task_count = selected_scan_count();
    pool.source_ip = source_ip;
    pool.results = results;
    if (pool.task_count == 0)
        return ;
    pool.completed = calloc(port_count, sizeof(*pool.completed));
    if (!pool.completed)
        fatal_error("Failed to allocate scan completion counters");
    error = pthread_mutex_init(&pool.lock, NULL);
    if (error != 0)
    {
        free(pool.completed);
        fatal_error(strerror(error));
    }
    worker_count = speedup;
    if ((size_t)worker_count > port_count * pool.task_count)
        worker_count = (int)(port_count * pool.task_count);
    i = 0;
    while (i < worker_count && g_opts->is_running)
    {
        workers[i].pool = &pool;
        workers[i].source_port = worker_source_port(source_port, i);
        workers[i].pcap = open_pcap(device, workers[i].source_port, target_ip);
        workers[i].error = 0;
        workers[i].target_ip = target_ip;
        i++;
    }
    worker_count = i;
    created = 0;
    error = 0;
    while (created < worker_count && g_opts->is_running)
    {
        result = pthread_create(&threads[created], NULL,
            scan_worker, &workers[created]);
        if (result != 0)
        {
            error = result;
            break;
        }
        created++;
    }
    i = 0;
    while (i < created)
    {
        result = pthread_join(threads[i], NULL);
        if (result != 0)
        {
            printf("Error: %s\n", strerror(result));
            exit(1);
        }
        if (error == 0 && workers[i].error != 0)
            error = workers[i].error;
        i++;
    }
    i = 0;
    while (i < worker_count)
    {
        pcap_close(workers[i].pcap);
        i++;
    }
    result = pthread_mutex_destroy(&pool.lock);
    if (error == 0 && result != 0)
        error = result;
    if (error != 0)
    {
        free(pool.completed);
        fatal_error(strerror(error));
    }
    free(pool.completed);
}

static void run_sequential_scans(int sockfd, pcap_t *pcap,
    struct in_addr source_ip, int *ports, size_t port_count,
    t_port_result *results, uint16_t source_port, struct in_addr target_ip)
{
    const char  *state;
    size_t      port_index;
    int         scan;

    port_index = 0;
    while (port_index < port_count && g_opts->is_running)
    {
        scan = 0;
        while (scan < SCAN_COUNT && g_opts->is_running)
        {
            if (g_opts->scans[scan])
            {
                state = scan_port(sockfd, pcap, source_ip, ports[port_index],
                        scan, source_port, target_ip);
                if (!state)
                    fatal_error(strerror(errno));
                results[port_index].states[scan] = state;
            }
            scan++;
        }
        if (g_opts->is_running)
            results[port_index].is_scanned = true;
        port_index++;
    }
}

void    trace(struct in_addr target_ip)
{
    int             *ports = g_opts->ports;
    int             sockfd;
    int             speedup;
    pcap_t          *pcap;
    char            *device;
    struct in_addr  source_ip;
    struct timeval  start, end;
    char            *hostname;

    t_port_result   *results;

    source_ip = get_source_ip(target_ip);
    sockfd = open_raw_socket();
    results = calloc(g_opts->port_count, sizeof(*results));
    if (!results)
    {
        close(sockfd);
        fatal_error("Failed to allocate scan results");
    }
    hostname = get_hostname(to_str(target_ip));
    printf("Target IP address: %s (%s)\n", hostname, to_str(target_ip));

    uint16_t source_port = get_option(OPT_SOURCE_PORT)->value;

    printf("Source port: %d\n", source_port);
    printf("Packet TLL: %d\n", get_option(OPT_TTL)->value);
    printf("Ports to scan: %ld\n", g_opts->port_count);
    printf("Scanning...\n");

    speedup = get_option(OPT_SPEEDUP)->value;
    device = get_pcap_device(source_ip);
    pcap = NULL;
    if (speedup == 0)
        pcap = open_pcap(device, source_port, target_ip);
    gettimeofday(&start, NULL);

    for (size_t i = 0; i < g_opts->port_count; i++)
        results[i].port = ports[i];
    if (speedup == 0)
        run_sequential_scans(sockfd, pcap, source_ip, ports,
            g_opts->port_count, results, source_port, target_ip);
    else
        run_parallel_scans(sockfd, source_ip, ports, g_opts->port_count,
            results, speedup, source_port, device, target_ip);
    gettimeofday(&end, NULL);
    long long diff_ms = (end.tv_sec - start.tv_sec) * 1000LL + 
                    (end.tv_usec - start.tv_usec) / 1000LL;
    printf("Performed scans in %lldms\n", diff_ms);

    if (pcap) pcap_close(pcap);
    if (sockfd >= 0) close(sockfd);

    print_final_results(results, g_opts->port_count, target_ip);
    if (results) free(results);
    if (hostname) free(hostname);
    if (device) free(device);
}
