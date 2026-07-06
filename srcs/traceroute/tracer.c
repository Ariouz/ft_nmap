#include "ft_nmap.h"

static struct icmphdr *recv_ttl_socket(int sockfd_icmp, fd_set *read_set, t_requests requests[3], int request_no)
{
    FD_ZERO(read_set);
    FD_SET(sockfd_icmp, read_set);
        
    size_t bytes = wait_socket(sockfd_icmp, read_set);
    if (bytes == (size_t) -1)
        return NULL ;
        
    if (!FD_ISSET(sockfd_icmp, read_set)) return NULL;
    FD_CLR(sockfd_icmp, read_set);
        
    char			rcv_buf[1024];
    socklen_t slen;
        
    slen = sizeof(struct sockaddr_in);
    size_t rcv_bytes = recvfrom(sockfd_icmp, rcv_buf, sizeof(rcv_buf), 0, (struct sockaddr *) &requests[request_no].responder, &slen);
        
    if (rcv_bytes < (size_t) (sizeof(struct iphdr) + sizeof(struct icmphdr))) return NULL;
        
    struct icmphdr *rcv_icmp = (struct icmphdr *)(rcv_buf + sizeof(struct iphdr));
        
    return rcv_icmp;
}

void    process_tll(int ttl, int payload_size, int port, int sockfd_udp, int sockfd_icmp)
{
    fd_set read_set;
    t_requests requests[3];


    for (int request_no = 0; request_no < 3; request_no++)
    {
        if (setsockopt(sockfd_udp, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
            fatal_error(strerror(errno));
        
        send_socket(g_opts->target_ip, sockfd_udp, payload_size, port);
        requests[request_no].rtt = -1;
        
        struct timeval start;
        gettimeofday(&start, NULL);
        struct icmphdr *rcv_icmp = recv_ttl_socket(sockfd_icmp, &read_set, requests, request_no);
        if (rcv_icmp == NULL) continue;

        struct timeval end;
        gettimeofday(&end, NULL);
        float rtt = (get_time_us(end) - get_time_us(start)) / (float) 1000.0;
        requests[request_no].rtt = rtt;
        
        if (rcv_icmp->type == ICMP_ECHOREPLY) {
            g_opts->is_running = false;
            break;
        }

        if (rcv_icmp->type == ICMP_TIME_EXCEEDED && rcv_icmp->code == ICMP_EXC_TTL) ; // no-op
        else if (rcv_icmp->type == ICMP_DEST_UNREACH && rcv_icmp->code == ICMP_PORT_UNREACH) {
            g_opts->is_running = false;
            break;
        } else continue;
        
    }

    process_results(ttl, requests);
}


void    trace()
{
    int sockfd_udp = g_opts->sockfd_udp;
    int sockfd_icmp = g_opts->sockfd_icmp;
    int max_ttl = get_option(OPT_MAX_TTL)->value;
    int ttl = get_option(OPT_FIRST_TTL)->value;
    int payload_size = 60;
    int port = get_option(OPT_PORT)->value;

    if (get_option(OPT_NO_DNS)->value == true)
        printf("ft_nmap to %s %d hops max, %d byte packets\n", to_str(g_opts->target_ip), max_ttl, payload_size);
    else
        printf("ft_nmap to %s (%s), %d hops max, %d byte packets\n",
            g_opts->hostname, to_str(g_opts->target_ip), max_ttl, payload_size);


    while (ttl <= max_ttl && g_opts->is_running)
    {
        process_tll(ttl, payload_size, port, sockfd_udp, sockfd_icmp);
        ttl++;
        port++;
    }

}