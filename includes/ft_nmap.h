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
# include <netinet/udp.h>
# include <arpa/inet.h>
# include <netdb.h>
# include <errno.h>
# include <getopt.h>
# include <signal.h>
# include <stdint.h>
# include <pthread.h>
# include <pcap.h>

# ifndef ICMP_DEST_UNREACH
#  define ICMP_DEST_UNREACH ICMP_UNREACH
#  define ICMP_HOST_UNREACH ICMP_UNREACH_HOST
#  define ICMP_PROT_UNREACH ICMP_UNREACH_PROTOCOL
#  define ICMP_PORT_UNREACH ICMP_UNREACH_PORT
#  define ICMP_NET_ANO ICMP_UNREACH_NET_PROHIB
#  define ICMP_HOST_ANO ICMP_UNREACH_HOST_PROHIB
#  define ICMP_PKT_FILTERED ICMP_UNREACH_FILTER_PROHIB
# endif

# define true 1
# define false 0

# define DEFAULT_TTL 64
# define MAX_THREADS 250
# define MAX_PORTS 1024

# define OPT_SOURCE_PORT 'g'
# define OPT_TTL 't'
# define OPT_OPEN 'o'
# define OPT_REASON 'r'
# define OPT_SPEEDUP 's'
# define OPT_BADSUM 'b'
# define OPT_NO_DNS 'n'

# define SCAN_OPEN            "open"
# define SCAN_CLOSED          "closed"
# define SCAN_FILTERED        "filtered"
# define SCAN_UNFILTERED      "unfiltered"
# define SCAN_OPEN_FILTERED   "open|filtered"

# define MAX_OPTS 16

#define SCAN_OPEN "open"
#define SCAN_CLOSED "closed"
#define SCAN_FILTERED "filtered"

typedef int bool;

typedef struct s_ip_header {
# if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    unsigned char   ihl:4;
    unsigned char   version:4;
# else
    unsigned char   version:4;
    unsigned char   ihl:4;
# endif
    uint8_t         tos;
    uint16_t        tot_len;
    uint16_t        id;
    uint16_t        frag_off;
    uint8_t         ttl;
    uint8_t         protocol;
    uint16_t        check;
    uint32_t        saddr;
    uint32_t        daddr;
}   t_ip_header;

typedef struct s_tcp_header {
    uint16_t        source;
    uint16_t        dest;
    uint32_t        seq;
    uint32_t        ack_seq;
# if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    unsigned char   res1:4;
    unsigned char   doff:4;
    unsigned char   fin:1;
    unsigned char   syn:1;
    unsigned char   rst:1;
    unsigned char   psh:1;
    unsigned char   ack:1;
    unsigned char   urg:1;
    unsigned char   ece:1;
    unsigned char   cwr:1;
# else
    unsigned char   doff:4;
    unsigned char   res1:4;
    unsigned char   cwr:1;
    unsigned char   ece:1;
    unsigned char   urg:1;
    unsigned char   ack:1;
    unsigned char   psh:1;
    unsigned char   rst:1;
    unsigned char   syn:1;
    unsigned char   fin:1;
# endif
    uint16_t        window;
    uint16_t        check;
    uint16_t        urg_ptr;
}   t_tcp_header;

typedef struct s_udp_header {
    uint16_t        source;
    uint16_t        dest;
    uint16_t        len;
    uint16_t        check;
}   t_udp_header;

typedef struct s_icmp_header {
    uint8_t         type;
    uint8_t         code;
    uint16_t        checksum;
    uint32_t        rest;
}   t_icmp_header;

typedef struct s_requests {
    float rtt;
    struct sockaddr_in responder;
}  t_requests;

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

typedef struct s_port_result {
    int         port;
    const char  *states[SCAN_COUNT];
    bool        is_scanned;
}   t_port_result;

typedef struct s_option {
    char    code;
    char    *description;
    int     value;
    bool    requires_value;
}   t_option;

typedef struct s_opts {
    t_option        **options;
    t_option        **def_options;
    size_t          size;
    size_t          def_size;
    bool            is_running;
    int             sockfd_icmp;
    int             sockfd_udp;
    struct in_addr  *targets;
    size_t          target_count;
    int             scans[SCAN_COUNT];

    int             *ports;
    size_t          port_count;
}   t_opts;

extern t_opts *g_opts;

struct in_addr  resolve_ip(const char *target);
char            *to_str(const struct in_addr addr);
char*           get_hostname(const char *ip_str);

void            handle_signals();

void            init_cli_options();
t_option        *create_option(int code, char *description, int default_value, bool requires_value);
void            add_option(int code, char *description, int default_value, bool requires_value);
void            save_option(t_option *option);

bool            set_option(int opt, char *optarg);
int             parse_opt_int(char *value, int min, int max);
bool            process_option(t_option *option, char *value);

t_option        *get_option(int code);
void            parse_cli_options(int argc, char **argv);
t_option        *get_default_if_not_opt(int code);

void	        parse_types(char *input);
void            parse_port_option(char *arg);
void            add_target(const char *ip);
void            parse_file(const char *filename);

struct sockaddr_in  get_sockaddr(struct in_addr target_ip, int port);

void            print_help();

void            clean_free();
void            free_options(t_option **options, size_t opt_len);

void            exit_error();
void            fatal_error(char *msg);
void            clean_exit(int code);

long long       get_time_ms(struct timeval tv);
int		        multisleep(long max_time_millis, long increment);

int             split (char *str, char c, char ***arr);

void                fill_ip_header(t_ip_header *ip, struct in_addr source_ip, struct in_addr target_ip, uint16_t total_len, uint8_t protocol);
const unsigned char *get_ip_packet(const unsigned char *packet, int datalink);
unsigned short      checksum(void *data, size_t len);
void                trace(struct in_addr target_ip);
const char      *scan_tcp_port(int sockfd, pcap_t *pcap, struct in_addr source_ip, uint16_t port, t_scan scan, uint16_t source_port, struct in_addr target_ip);
const char      *scan_udp_port(int sockfd, pcap_t *pcap, struct in_addr source_ip, uint16_t port, uint16_t source_port, struct in_addr target_ip);

void            print_final_results(t_port_result *results, size_t port_count, struct in_addr target_ip);

#endif
