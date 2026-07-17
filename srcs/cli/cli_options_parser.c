#include "ft_nmap.h"

struct option long_options[] = {
    {"help",    no_argument,       0, 'h'},
    {"ports",   required_argument, 0, 'p'},
    {"ip",      required_argument, 0, 'i'},
    {"file",    required_argument, 0, 'f'},
    {"scan",    required_argument, 0, 'c'},
    {"speedup", required_argument, NULL, OPT_SPEEDUP},
    #ifdef BONUS
    {"source-port",    required_argument, 0, 'g'},
    {"ttl",    required_argument, 0, 't'},
    {"open",    no_argument, 0, 'o'},
    {"reason",    no_argument, 0, 'r'},
    {"badsum",  no_argument, 0, OPT_BADSUM},
    {"no-dns",  no_argument, 0, OPT_NO_DNS},
    #endif
    {0, 0, 0, 0}
};

bool    process_option(t_option *option, char *value)
{
    if (!option->requires_value)
    {
        option->value = true;
        return true;
    }
    #ifdef BONUS
    if (option->code == OPT_SOURCE_PORT)
        option->value = parse_opt_int(value, 1, 65535);
    if (option->code == OPT_TTL)
        option->value = parse_opt_int(value, 1, INT32_MAX);
    #endif

    if (option->code == OPT_SPEEDUP)
        option->value = parse_opt_int(value, 0, MAX_THREADS);

    return true;
}


void parse_cli_options(int argc, char **argv) {
    int opt, option_index = 0;
    #ifndef BONUS
    char *options = ":hp:i:f:s:c:";
    #else
    char *options = ":hp:i:f:s:c:g:t:orbn";
    #endif

    opterr = 0;
    while ((opt = getopt_long(argc, argv, options, long_options, &option_index)) != -1) {
        switch (opt) {
            case 'p': parse_port_option(optarg); break;
            case 'i': add_target(optarg); break;
            case 'f': parse_file(optarg); break;
            case 'c': parse_types(optarg); break;
            case 's': set_option(opt, optarg); break;
            case 'h': print_help(); exit(0);
            #ifdef BONUS
            case 'g': set_option(opt, optarg); break;
            case 't': set_option(opt, optarg); break;
            case 'o': set_option(opt, optarg); break;
            case 'b': set_option(opt, optarg); break;
            case 'r': set_option(opt, optarg); break;
            case 'n': set_option(opt, optarg); break;
            #endif
            case ':':
                fatal_error("Option requires a value");
                break;
            case '?':
                fatal_error("Invalid option, use --help for options list");
                break;
        }
    }
}

bool    set_option(int opt, char *optarg)
{
    t_option *option;

    option = get_option(opt);
    if (!option)
        fatal_error("Invalid option, use --help for options list");

    return process_option(option, optarg);
}

int parse_opt_int(char *value, int min, int max)
{
    char *endptr;
    long val = 0;
    errno = 0;

    val = strtol(value, &endptr, 10);

    if (endptr == value)
        fatal_error("Option value must be a valid integer");

    if (*endptr != '\0')
        fatal_error("Option value must be a valid integer");

    if (errno != 0)
        fatal_error(strerror(errno));

    if (val < min)
        fatal_error("Option value is too low");

    if (val > max)
        fatal_error("Option value is too big");

    return (int) val;
}


void print_help() {
    printf("Usage: ft_nmap [options]\n\n");
    printf("Options:\n");
    printf("  -h, --help\t\tDisplay this help list\n");
    printf("  -p, --ports <ports>\tScan only specified ports (e.g., 80,443)\n");
    printf("  -i, --ip <ip>\t\tTarget IP address\n");
    printf("  -f, --file <file>\tRead target from file\n");
    printf("  -s, --speedup <n>\tNumber of parallel threads (default 0, max 250)\n");
    printf("  -c, --scan <type>\tSpecify scan type (SYN, ACK, FIN, XMAS, NULL, UDP)\n");

    #ifdef BONUS
    printf("\nBonus Options:\n");
    printf("  -g, --source-port <port>\tUse specific source port\n");
    printf("  -t, --ttl <ttl>\t\tSet time-to-live\n");
    printf("  -o, --open\t\t\tOnly show open ports\n");
    printf("  -r, --reason\t\t\tDisplay the reason a port is in a particular state\n");
    printf("  --badsum\t\t\tSend packets with a zero checksum\n");
    printf("  -n, --no-dns\t\tNever perform DNS resolution\n");
    #endif

    printf("\n");

    clean_exit(0);
}
