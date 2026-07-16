#include "ft_nmap.h"

static void parse_port_error(char *copy, char *message)
{
    free(copy);
    fatal_error(message);
}

static int parse_port_value(char *value, char *copy)
{
    char    *endptr;
    long    port;

    errno = 0;
    port = strtol(value, &endptr, 10);
    if (endptr == value || *endptr != '\0')
        parse_port_error(copy, "Option value must be a valid integer");
    if (errno != 0)
        parse_port_error(copy, strerror(errno));
    if (port < 1)
        parse_port_error(copy, "Option value is too low");
    if (port > 65535)
        parse_port_error(copy, "Option value is too big");
    return (int)port;
}

static void add_port(int port, char *copy) {
    int *ports;

    if (port < 1 || port > 65535) return;
    
    for (size_t i = 0; i < g_opts->port_count; i++) {
        if (g_opts->ports[i] == port) return;
    }

    if (g_opts->port_count >= MAX_PORTS)
        parse_port_error(copy, "Too many ports: maximum is 1024");
    ports = realloc(g_opts->ports, sizeof(int) * (g_opts->port_count + 1));
    if (!ports)
        parse_port_error(copy, "Memory allocation failed");
    g_opts->ports = ports;
    g_opts->ports[g_opts->port_count] = port;
    g_opts->port_count++;
}

void parse_port_option(char *arg)
{
    char *copy = strdup(arg);
    if (!copy) fatal_error("Memory allocation failed");

    char *token = strtok(copy, ",");
    while (token) {
        char *dash = strchr(token, '-');
        if (dash) {
            *dash = '\0';
            int start = parse_port_value(token, copy);
            int end = parse_port_value(dash + 1, copy);
            
            if (start > end)
                parse_port_error(copy,
                    "Invalid port range: start is greater than end");
            
            for (int i = start; i <= end; i++)
                add_port(i, copy);
        } else {
            int port = parse_port_value(token, copy);
            add_port(port, copy);
        }
        token = strtok(NULL, ",");
    }
    free(copy);
}
