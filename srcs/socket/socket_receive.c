#include "ft_nmap.h"

int     open_recv_socket()
{
    int sockfd_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sockfd_icmp == -1)
		fatal_error(strerror(errno));

    return sockfd_icmp;
}

size_t wait_socket(int sockfd, fd_set *read_set)
{
	struct timeval timeout = {get_option(OPT_SOCK_TIMEOUT)->value, 0};
    int res = 0;
    res = select(sockfd + 1, read_set, NULL, NULL, &timeout);
	if (!is_runnning()) return -1;
	if (res == -1)
		fatal_error(strerror(errno));
	if (res == 0) return -1;

    return (size_t) res;
}