#include "ft_nmap.h"

const char *scan_to_string(t_scan scan)
{
    static const char *names[] = {
        "SYN",
        "NULL",
        "ACK",
        "FIN",
        "XMAS",
        "UDP"
    };

    return names[scan];
}

static bool is_open(const char *res) {
    return strcmp(res, "open") == 0;
}

static bool is_any_scan_open(t_port_result res) {
    size_t  i = 0;
    while (i < SCAN_COUNT) {
        if (is_open(res.states[i])) return true;
        i++;
    }
    return false;
}

static char *get_conclusion(t_port_result res) {
    if (is_any_scan_open(res)) return "Open";
    return "Closed";
}


static void print_table_header(void)
{
    printf("%-8s %-20s %-50s %-10s\n", "Port", "Service", "Results", "Conclusion");
    printf("---------------------------------------------------------------------------------------------------\n");
}

static void print_port_row(t_port_result res)
{
    struct servent *serv = getservbyport(htons(res.port), "tcp");
    char *serv_name = serv ? serv->s_name : "Unassigned";

    printf("%-8d %-20s ", res.port, serv_name);
    
    for (int scan = 0; scan < SCAN_COUNT; scan++) {
        printf("%s(%s) ", scan_to_string(scan), res.states[scan]);
        
        if ((scan + 1) % 3 == 0 && (scan + 1) < SCAN_COUNT) 
            printf("\n%-28s", "");
    }

    printf(" %-10s\n", get_conclusion(res));
}

void print_final_results(t_port_result *results, size_t port_count)
{
    printf("\nIP address: %s\n", to_str(g_opts->target_ip));
    
    printf("Open ports:\n");
    print_table_header();
    for (size_t i = 0; i < port_count; i++) {
        if (is_any_scan_open(results[i]))
            print_port_row(results[i]);
    }

    printf("\nClosed/Filtered/Unfiltered ports:\n");
    print_table_header();
    for (size_t i = 0; i < port_count; i++) {
        if (!is_any_scan_open(results[i]))
            print_port_row(results[i]);
    }
}

