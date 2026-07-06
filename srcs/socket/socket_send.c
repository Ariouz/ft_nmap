#include "ft_nmap.h"

int     open_send_socket()
{
	int sockfd_udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sockfd_udp == -1)
		fatal_error(strerror(errno));

    return sockfd_udp;
}

struct sockaddr_in  get_sockaddr(struct in_addr target_ip, int port)
{
    struct sockaddr_in sockaddr;
	sockaddr.sin_addr = target_ip;
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(port);

    return sockaddr;
}

void    send_socket(struct in_addr target_ip, int sockfd, size_t payload_size, int port)
{
	struct sockaddr_in sockaddr;
    sockaddr = get_sockaddr(target_ip, port);

	unsigned char data[1024];
	memset(data, 0, payload_size);


	int sent_bytes = 0;
	sent_bytes = sendto(sockfd, data, payload_size, 0, (struct sockaddr *) &sockaddr, sizeof(sockaddr));

	if (sent_bytes == -1)
	{
		perror("sendto");
		return ;
	}

}