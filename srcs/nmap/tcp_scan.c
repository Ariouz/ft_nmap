#include "ft_nmap.h"

typedef struct s_tcp_packet {
    struct iphdr    ip;
    struct tcphdr   tcp;
}   t_tcp_packet;

typedef struct s_tcp_pseudo_header {
    uint32_t    source_addr;
    uint32_t    dest_addr;
    uint8_t     placeholder;
    uint8_t     protocol;
    uint16_t    tcp_length;
}   t_tcp_pseudo_header;

static void fill_tcp_header(struct tcphdr *tcp, int port, uint16_t source_port)
{
    memset(tcp, 0, sizeof(*tcp));
    tcp->source = htons(source_port);
    tcp->dest = htons(port);
    tcp->seq = htonl(1);
    tcp->doff = sizeof(struct tcphdr) / 4;
    tcp->window = htons(64240);
}

static void fill_tcp_checksum(t_tcp_packet *packet)
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

static void fill_tcp_flags(struct tcphdr *tcp, t_scan scan)
{
    switch (scan)
    {
        case SCAN_SYN:
            tcp->syn = 1;
            break;

        case SCAN_ACK:
            tcp->ack = 1;
            break;

        case SCAN_FIN:
            tcp->fin = 1;
            break;

        case SCAN_NULL:
            break;

        case SCAN_XMAS:
            tcp->fin = 1;
            tcp->psh = 1;
            tcp->urg = 1;
            break;

        default:
            break;
    }
}

static void send_tcp_packet(int sockfd, struct in_addr source_ip, int port, t_scan scan, uint16_t source_port)
{
    t_tcp_packet packet;
    struct sockaddr_in  target;

    memset(&packet, 0, sizeof(packet));

    fill_ip_header(&packet.ip, source_ip, g_opts->target_ip, sizeof(t_tcp_packet), IPPROTO_TCP);
    fill_tcp_header(&packet.tcp, port, source_port);
    fill_tcp_flags(&packet.tcp, scan);
    fill_tcp_checksum(&packet);

    target = get_sockaddr(g_opts->target_ip, port);

    if (sendto(sockfd, &packet, sizeof(packet), 0,
            (struct sockaddr *)&target, sizeof(target)) == -1)
        fatal_error(strerror(errno));
}

static const char *read_tcp_response(pcap_t *pcap, int port, t_scan scan, uint16_t source_port)
{
    struct pcap_pkthdr      *header;
    const unsigned char     *packet;
    const unsigned char     *ip_packet;
    struct iphdr            *ip;
    struct tcphdr           *tcp;
    struct icmphdr          *icmp;
    struct iphdr            *inner_ip;
    struct tcphdr           *inner_tcp;
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
            break;

        result = pcap_next_ex(pcap, &header, &packet);

        if (result == 0)
        {
            multisleep(10, 1);
            continue;
        }
        if (result == -1)
            fatal_error(pcap_geterr(pcap));
        if (result == -2)
            break;

        ip_packet = get_ip_packet(packet, datalink);
        if (!ip_packet)
            continue;
        if (header->caplen < (size_t)(ip_packet - packet) + sizeof(struct iphdr))
            continue;

        ip = (struct iphdr *)ip_packet;
        if (ip->saddr != g_opts->target_ip.s_addr)
            continue;

        /* ICMP */

        if (ip->protocol == IPPROTO_ICMP)
        {
            icmp = (struct icmphdr *)(ip_packet + ip->ihl * 4);

            if (icmp->type != ICMP_DEST_UNREACH)
                continue;

            if (icmp->code != ICMP_HOST_UNREACH &&
                icmp->code != ICMP_PROT_UNREACH &&
                icmp->code != ICMP_NET_ANO &&
                icmp->code != ICMP_HOST_ANO &&
                icmp->code != ICMP_PKT_FILTERED)
                continue;

            inner_ip = (struct iphdr *)(icmp + 1);

            if (inner_ip->protocol != IPPROTO_TCP)
                continue;

            inner_tcp = (struct tcphdr *)((unsigned char *)inner_ip +
                inner_ip->ihl * 4);

            if (ntohs(inner_tcp->source) != source_port ||
                ntohs(inner_tcp->dest) != port)
                continue;

            return SCAN_FILTERED;
        }

        /* TCP */

        if (ip->protocol != IPPROTO_TCP)
            continue;

        tcp = (struct tcphdr *)(ip_packet + ip->ihl * 4);

        if (ntohs(tcp->source) != port ||
            ntohs(tcp->dest) != source_port)
            continue;

        switch (scan)
        {
            case SCAN_SYN:
                if (tcp->syn && tcp->ack)
                    return SCAN_OPEN;
                if (tcp->rst)
                    return SCAN_CLOSED;
                break;

            case SCAN_ACK:
                if (tcp->rst)
                    return SCAN_UNFILTERED;
                break;

            case SCAN_FIN:
            case SCAN_NULL:
            case SCAN_XMAS:
                if (tcp->rst)
                    return SCAN_CLOSED;
                break;

            default:
                break;
        }
    }

    if (scan == SCAN_SYN || scan == SCAN_ACK)
        return SCAN_FILTERED;

    return SCAN_OPEN_FILTERED;
}

const char *scan_tcp_port(int sockfd, pcap_t *pcap, struct in_addr source_ip, uint16_t port, t_scan scan, uint16_t source_port)
{
    send_tcp_packet(sockfd, source_ip, port, scan, source_port);
    return read_tcp_response(pcap, port, scan, source_port);
}