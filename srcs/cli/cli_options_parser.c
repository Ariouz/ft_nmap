#include "ft_nmap.h"

bool    process_option(t_option *option, char *value)
{
    if (option->code == OPT_FIRST_TTL
        || option->code == OPT_MAX_TTL
        || option->code == OPT_SOCK_TIMEOUT)
        option->value = parse_opt_int(value, 1, INT32_MAX);
    
    else if (option->code == OPT_NO_DNS)
        option->value = 1;

    else if (option->code == OPT_PORT)
        option->value = parse_opt_int(value, 1, 65535);

    return true;
}

void parse_cli_options(int argc, char **argv) {
    struct option long_options[] = {
        {"help",    no_argument,       0, 'h'},
        {"ports",   required_argument, 0, 'p'},
        {"ip",      required_argument, 0, 'i'},
        {"file",    required_argument, 0, 'f'},
        {"speedup", required_argument, 0, 's'},
        {"scan",    required_argument, 0, 'c'},
        {0, 0, 0, 0}
    };

    int opt, option_index = 0;
    while ((opt = getopt_long(argc, argv, "h:p:i:f:s:c:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'p': parse_port_option(optarg); break;
            case 'i': /* Logique IP */ break;
            // ... autres options
            case 'h': print_help(); exit(0);
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

    if (errno != 0 && val == 0)
        fatal_error(strerror(errno));

    if (val < min)
        fatal_error("Option value is too low");

    if (val > max)
        fatal_error("Option value is too big");

    return (int) val;
}