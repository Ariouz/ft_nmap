#ifndef FT_NMAP_H
# define FT_NMAP_H
# define __USE_POSIX2

# include <unistd.h>
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <fcntl.h>
# include <sys/socket.h>
# include <sys/time.h>
# include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/ip_icmp.h>
# include <netinet/tcp.h>
# include <arpa/inet.h>
# include <netdb.h>
# include <errno.h>
# include <getopt.h>
# include <signal.h>
# include <stdint.h>
# include <pcap.h>

# define true 1
# define false 0

# define SOCK_RTT_BATCH_SIZE 10

# define OPT_FIRST_TTL 'f'
# define OPT_MAX_TTL 'm'
# define OPT_PORT 'p'
# define OPT_SOCK_TIMEOUT 'w'
# define OPT_NO_DNS 'n'

# define SCAN_OPEN            "open"
# define SCAN_CLOSED          "closed"
# define SCAN_FILTERED        "filtered"
# define SCAN_UNFILTERED      "unfiltered"
# define SCAN_OPEN_FILTERED   "open|filtered"

# define MAX_OPTS 16

typedef int bool;

typedef struct s_requests {
    float rtt;
    struct sockaddr_in responder;
}  t_requests;

typedef struct s_option {
    char    code;
    char    *description;
    int     value;
    bool    requires_value;
}   t_option;

typedef enum e_scan
{
    SCAN_SYN,
    SCAN_NULL,
    SCAN_ACK,
    SCAN_FIN,
    SCAN_XMAS,
    SCAN_UDP,
    SCAN_COUNT
} t_scan;

typedef struct s_opts {
    t_option        **options;
    size_t          size;
    char            *hostname;
    bool            is_running;
    int             sockfd_icmp;
    int             sockfd_udp;
    struct in_addr  target_ip;
    int             scans[SCAN_COUNT];
}   t_opts;

extern t_opts *g_opts;

struct in_addr  resolve_ip(const char *target);
char            *to_str(const struct in_addr addr);

void            handle_signals();

int             open_send_socket();
int             open_recv_socket();

void            init_cli_options();
t_option        *create_option(int code, char *description, int default_value, bool requires_value);
void            add_option(int code, char *description, int default_value, bool requires_value);
void            save_option(t_option *option);

bool            set_option(int opt, char *optarg);
int             parse_opt_int(char *value, int min, int max);
bool            process_option(t_option *option, char *value);

t_option        *get_option(int code);
void            parse_cli_options(int argc, char **argv);

void	        parse_types(char *input);

struct sockaddr_in  get_sockaddr(struct in_addr target_ip, int port);
void                send_socket(struct in_addr target_ip, int sockfd, size_t payload_size, int port);
size_t              wait_socket(int sockfd, fd_set *read_set);
void                process_results(int ttl, struct s_requests requests[3]);

void            print_help();

void            clean_free();
void            free_options(t_option **options, size_t opt_len);

bool            is_runnning();

void            exit_error();
void            fatal_error(char *msg);
void            clean_exit(int code);

long long       get_time_ms(struct timeval tv);
long long       get_time_us(struct timeval tv);
int		        multisleep(long max_time_millis, long increment);

int             split (char *str, char c, char ***arr);

void            trace();

#endif
