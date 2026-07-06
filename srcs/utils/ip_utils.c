#include "ft_nmap.h" 

struct in_addr resolve_ip(const char *hostname)
{
    struct addrinfo hints;
	struct addrinfo *res;
    struct in_addr ip_addr;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints, &res) != 0) {
        ip_addr.s_addr = INADDR_NONE;
        return ip_addr;
    }

    struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
    ip_addr = ipv4->sin_addr;

    freeaddrinfo(res);
    return ip_addr;
}

char    *to_str(const struct in_addr addr)
{
    return inet_ntoa(addr);
}