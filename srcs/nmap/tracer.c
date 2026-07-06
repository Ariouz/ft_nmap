#include "ft_nmap.h"

#define SYN_SOURCE_PORT 42424
#define SCAN_OPEN "open"
#define SCAN_CLOSED "closed"
#define SCAN_FILTERED "filtered"

struct s_tcp_packet {
    struct iphdr    ip;
    struct tcphdr   tcp;
};

struct s_tcp_pseudo_header {
    uint32_t    source_addr;
    uint32_t    dest_addr;
    uint8_t     placeholder;
    uint8_t     protocol;
    uint16_t    tcp_length;
};

static unsigned short checksum(void *data, size_t len)
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

static void fill_ip_header(struct iphdr *ip, struct in_addr source_ip,
    struct in_addr target_ip)
{
    memset(ip, 0, sizeof(*ip));
    ip->ihl = 5;
    ip->version = 4;
    ip->tot_len = htons(sizeof(struct s_tcp_packet));
    ip->id = htons((unsigned short)getpid());
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = source_ip.s_addr;
    ip->daddr = target_ip.s_addr;
    ip->check = checksum(ip, sizeof(*ip));
}

static void fill_tcp_header(struct tcphdr *tcp, int port)
{
    memset(tcp, 0, sizeof(*tcp));
    tcp->source = htons(SYN_SOURCE_PORT);
    tcp->dest = htons(port);
    tcp->seq = htonl(1);
    tcp->doff = sizeof(struct tcphdr) / 4;
    tcp->syn = 1;
    tcp->window = htons(64240);
}

static void fill_tcp_checksum(struct s_tcp_packet *packet)
{
    struct s_tcp_pseudo_header  pseudo_header;
    unsigned char               checksum_buf[sizeof(pseudo_header)
        + sizeof(struct tcphdr)];

    pseudo_header.source_addr = packet->ip.saddr;
    pseudo_header.dest_addr = packet->ip.daddr;
    pseudo_header.placeholder = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_length = htons(sizeof(struct tcphdr));
    memcpy(checksum_buf, &pseudo_header, sizeof(pseudo_header));
    memcpy(checksum_buf + sizeof(pseudo_header), &packet->tcp,
        sizeof(struct tcphdr));
    packet->tcp.check = checksum(checksum_buf, sizeof(checksum_buf));
}

static void send_syn_packet(int sockfd, struct in_addr source_ip, int port)
{
    struct s_tcp_packet packet;
    struct sockaddr_in  target;

    memset(&packet, 0, sizeof(packet));
    fill_ip_header(&packet.ip, source_ip, g_opts->target_ip);
    fill_tcp_header(&packet.tcp, port);
    fill_tcp_checksum(&packet);
    target = get_sockaddr(g_opts->target_ip, port);
    if (sendto(sockfd, &packet, sizeof(packet), 0,
            (struct sockaddr *)&target, sizeof(target)) == -1)
        fatal_error(strerror(errno));
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

static pcap_t *open_pcap(uint16_t source_port)
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
        "tcp and src host %s and dst port %u",
        to_str(g_opts->target_ip), source_port);
    if (pcap_compile(handle, &program, filter, 1, 0) == -1)
        fatal_error(pcap_geterr(handle));
    if (pcap_setfilter(handle, &program) == -1)
        fatal_error(pcap_geterr(handle));
    pcap_freecode(&program);
    return handle;
}

static const unsigned char *get_ip_packet(const unsigned char *packet,
    int datalink)
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

static const char *read_syn_response(pcap_t *pcap, int port)
{
    struct pcap_pkthdr      *header;
    const unsigned char     *packet;
    const unsigned char     *ip_packet;
    struct iphdr            *ip;
    struct tcphdr           *tcp;
    int                     datalink;
    int                     result;
    struct timeval          start;
    struct timeval          now;
    long long               timeout_ms;

    datalink = pcap_datalink(pcap);
    gettimeofday(&start, NULL);
    timeout_ms = get_option(OPT_SOCK_TIMEOUT)->value * 1000LL;
    while (g_opts->is_running)
    {
        gettimeofday(&now, NULL);
        if (get_time_ms(now) - get_time_ms(start) >= timeout_ms)
            return SCAN_FILTERED;
        result = pcap_next_ex(pcap, &header, &packet);
        if (result == 0)
        {
            multisleep(10, 1);
            continue;
        }
        if (result == -1)
            fatal_error(pcap_geterr(pcap));
        if (result == -2)
            return SCAN_FILTERED;
        ip_packet = get_ip_packet(packet, datalink);
        if (!ip_packet || header->caplen < (size_t)(ip_packet - packet)
                + sizeof(struct iphdr))
            continue;
        ip = (struct iphdr *)ip_packet;
        if (ip->protocol != IPPROTO_TCP)
            continue;
        tcp = (struct tcphdr *)(ip_packet + (ip->ihl * 4));
        if (ntohs(tcp->source) != port || ntohs(tcp->dest) != SYN_SOURCE_PORT)
            continue;
        if (tcp->syn && tcp->ack)
            return SCAN_OPEN;
        if (tcp->rst)
            return SCAN_CLOSED;
    }
    return SCAN_FILTERED;
}

static const char *scan_syn_port(int sockfd, pcap_t *pcap,
    struct in_addr source_ip, int port)
{
    send_syn_packet(sockfd, source_ip, port);
    return read_syn_response(pcap, port);
}

void    trace()
{
    int             ports[] = {22, 80, 443, 8080};
    int             port_count = sizeof(ports) / sizeof(ports[0]);
    int             sockfd;
    pcap_t          *pcap;
    struct in_addr  source_ip;

    source_ip = get_source_ip(g_opts->target_ip);
    sockfd = open_raw_socket();
    pcap = open_pcap(SYN_SOURCE_PORT);
    if (get_option(OPT_NO_DNS)->value == true)
        printf("ft_nmap scan %s\n", to_str(g_opts->target_ip));
    else
        printf("ft_nmap scan %s (%s)\n", g_opts->hostname, to_str(g_opts->target_ip));
    printf("Scan: SYN\n");
    for (int i = 0; i < port_count && g_opts->is_running; i++)
        printf("%d/tcp SYN(%s)\n", ports[i],
            scan_syn_port(sockfd, pcap, source_ip, ports[i]));
    pcap_close(pcap);
    close(sockfd);
}
