#include "ft_nmap.h"

struct sockaddr_in  get_sockaddr(struct in_addr target_ip, int port)
{
    struct sockaddr_in sockaddr;
	sockaddr.sin_addr = target_ip;
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(port);

    return sockaddr;
}