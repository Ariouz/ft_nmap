#include "ft_nmap.h"

void add_port(int port) {
    if (port < 1 || port > 65535) return;
    
    for (size_t i = 0; i < g_opts->port_count; i++) {
        if (g_opts->ports[i] == port) return;
    }

    g_opts->ports = realloc(g_opts->ports, sizeof(int) * (g_opts->port_count + 1));
    g_opts->ports[g_opts->port_count] = port;
    g_opts->port_count++;
    printf("add port %d\n", port);
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
            int start = parse_opt_int(token, 1, 65535);
            int end = parse_opt_int(dash + 1, 1, 65535);
            
            if (start > end)
                fatal_error("Invalid port range: start is greater than end");
            
            for (int i = start; i <= end; i++)
                add_port(i);
        } else {
            int port = parse_opt_int(token, 1, 65535);
            add_port(port);
        }
        token = strtok(NULL, ",");
    }
    free(copy);
}