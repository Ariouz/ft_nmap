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

void fill_ip_header(struct iphdr *ip, struct in_addr source_ip, struct in_addr target_ip, uint16_t total_len, uint8_t protocol)
{
    memset(ip, 0, sizeof(*ip));

    ip->ihl = 5;
    ip->version = 4;
    ip->tot_len = htons(total_len);
    ip->id = htons((unsigned short)getpid());
    ip->ttl = 64;
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

static pcap_t *open_pcap()
{
    pcap_t              *handle;
    char                errbuf[PCAP_ERRBUF_SIZE];
    char                filter[128];
    struct bpf_program  program;

    handle = pcap_open_live("any", 65535, 0,
            get_option(OPT_SOCK_TIMEOUT)->value * 1000, errbuf);
    if (!handle)
        fatal_error(errbuf);
    if (pcap_setnonblock(handle, 1, errbuf) == -1)
        fatal_error(errbuf);
    snprintf(filter, sizeof(filter),
        "(tcp and src host %s) or "
        "(icmp and src host %s)",
        to_str(g_opts->target_ip),
        to_str(g_opts->target_ip));
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
    if (datalink == DLT_LINUX_SLL)
        return packet + 16;
    if (datalink == DLT_LINUX_SLL2)
        return packet + 20;
    if (datalink == DLT_RAW)
        return packet;
    return NULL;
}

const char *scan_to_string(t_scan scan)
{
    static const char *names[] = {
        "SYN",
        "NULL",
        "ACK",
        "FIN",
        "XMAS",
        "UDP"
    };

    return names[scan];
}

void    trace()
{
    int             *ports = g_opts->ports;
    int             sockfd;
    pcap_t          *pcap;
    struct in_addr  source_ip;
    struct timeval start, end;

    source_ip = get_source_ip(g_opts->target_ip);
    sockfd = open_raw_socket();
    if (get_option(OPT_NO_DNS)->value == true)
        printf("ft_nmap scan %s\n", to_str(g_opts->target_ip));
    else
        printf("ft_nmap scan %s (%s)\n", g_opts->hostname, to_str(g_opts->target_ip));
    

    uint16_t source_port = 42424;  //40000 + rand() % 20000;
    pcap = open_pcap();
    gettimeofday(&start, NULL);

    // scans
    for (size_t i = 0; i < g_opts->port_count && g_opts->is_running; i++)
    {
        printf("Port: %d\n", ports[i]);
        for (int scan = 0; scan < SCAN_COUNT && g_opts->is_running; scan++)
        {

            if (!g_opts->scans[scan])
                continue;

            struct pcap_pkthdr *h;
            const unsigned char *p;
            while (pcap_next_ex(pcap, &h, &p) == 1) ; // clear pcap cache

            const char *state;

            if (scan == SCAN_UDP)
                state = scan_udp_port(sockfd, pcap, source_ip, ports[i], source_port);
            else
                state = scan_tcp_port(sockfd, pcap, source_ip, ports[i], scan, source_port);

            printf("%d/%s %s(%s)\n",
                ports[i],
                scan == SCAN_UDP ? "udp" : "tcp",
                scan_to_string(scan),
                state);

        }
    }
    gettimeofday(&end, NULL);
    long long diff_ms = (end.tv_sec - start.tv_sec) * 1000LL + 
                    (end.tv_usec - start.tv_usec) / 1000LL;
    printf("Performed scans in %lldms\n", diff_ms);

    pcap_close(pcap);
    close(sockfd);
}
