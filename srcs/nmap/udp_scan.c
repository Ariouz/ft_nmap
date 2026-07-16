#include "ft_nmap.h"

typedef struct s_udp_packet
{
    struct iphdr    ip;
    struct udphdr   udp;
} t_udp_packet;

typedef struct s_udp_pseudo_header
{
    uint32_t    source_addr;
    uint32_t    dest_addr;
    uint8_t     zero;
    uint8_t     protocol;
    uint16_t    udp_length;
} t_udp_pseudo_header;

static void fill_udp_header(struct udphdr *udp, int port, uint16_t source_port)
{
    memset(udp, 0, sizeof(*udp));

    udp->source = htons(source_port);
    udp->dest = htons(port);
    udp->len = htons(sizeof(struct udphdr));
}

static void fill_udp_checksum(t_udp_packet *packet)
{
    struct s_udp_pseudo_header pseudo;
    unsigned char buf[sizeof(pseudo) + sizeof(struct udphdr)];

    pseudo.source_addr = packet->ip.saddr;
    pseudo.dest_addr = packet->ip.daddr;
    pseudo.zero = 0;
    pseudo.protocol = IPPROTO_UDP;
    pseudo.udp_length = htons(sizeof(struct udphdr));

    memcpy(buf, &pseudo, sizeof(pseudo));
    memcpy(buf + sizeof(pseudo), &packet->udp, sizeof(struct udphdr));

    packet->udp.check = checksum(buf, sizeof(buf));
}

static void send_udp_packet( int sockfd, struct in_addr source_ip, int port, uint16_t source_port, struct in_addr target_ip)
{
    t_udp_packet packet;
    struct sockaddr_in target;

    memset(&packet, 0, sizeof(packet));

    fill_ip_header(&packet.ip, source_ip, target_ip, sizeof(t_udp_packet), IPPROTO_UDP);

    fill_udp_header(&packet.udp, port, source_port);
    fill_udp_checksum(&packet);

    target = get_sockaddr(target_ip, port);

    if (sendto(sockfd, &packet, sizeof(packet), 0,
        (struct sockaddr *)&target, sizeof(target)) == -1)
        fatal_error(strerror(errno));
}

static const char *read_udp_response(pcap_t *pcap, int port, uint16_t source_port, struct in_addr target_ip)
{
    struct pcap_pkthdr      *header;
    const unsigned char     *packet;
    const unsigned char     *ip_packet;
    struct iphdr            *ip;
    struct udphdr           *udp;
    struct icmphdr          *icmp;
    struct iphdr            *inner_ip;
    struct udphdr           *inner_udp;
    int                     datalink;
    int                     result;
    struct timeval          start;
    struct timeval          now;
    long long               timeout_ms;

    datalink = pcap_datalink(pcap);
    gettimeofday(&start, NULL);
    timeout_ms = 1 * 1000LL; // todo ? get_option(OPT_SOCK_TIMEOUT)->valu

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

        ip = (struct iphdr *)ip_packet;
        if (ip->saddr != target_ip.s_addr)
            continue;

        /* UDP */

        if (ip->protocol == IPPROTO_UDP)
        {
            udp = (struct udphdr *)(ip_packet + ip->ihl * 4);

            if (ntohs(udp->source) == port &&
                ntohs(udp->dest) == source_port)
                return SCAN_OPEN;

            continue;
        }

        /* ICMP */

        if (ip->protocol != IPPROTO_ICMP)
            continue;

        icmp = (struct icmphdr *)(ip_packet + ip->ihl * 4);

        if (icmp->type != ICMP_DEST_UNREACH)
            continue;

        inner_ip = (struct iphdr *)(icmp + 1);

        if (inner_ip->protocol != IPPROTO_UDP)
            continue;

        inner_udp = (struct udphdr *)((unsigned char *)inner_ip +
            inner_ip->ihl * 4);

        if (ntohs(inner_udp->source) != source_port ||
            ntohs(inner_udp->dest) != port)
            continue;

        switch (icmp->code)
        {
            case ICMP_PORT_UNREACH:
                return SCAN_CLOSED;

            case ICMP_HOST_UNREACH:
            case ICMP_PROT_UNREACH:
            case ICMP_NET_ANO:
            case ICMP_HOST_ANO:
            case ICMP_PKT_FILTERED:
                return SCAN_FILTERED;

            default:
                break;
        }
    }

    return SCAN_OPEN_FILTERED;
}

const char *scan_udp_port(int sockfd, pcap_t *pcap, struct in_addr source_ip, uint16_t port, uint16_t source_port, struct in_addr target_ip)
{
    send_udp_packet(sockfd, source_ip, port, source_port, target_ip);
    return read_udp_response(pcap, port, source_port, target_ip);
}