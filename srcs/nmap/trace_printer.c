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
        if (!res.states[i]) {
            i++;
            continue;
        }
        if (is_open(res.states[i])) return true;
        i++;
    }
    return false;
}

const char *get_conclusion(t_port_result res) {
    if (res.states[SCAN_SYN]) {
        if (strcmp(res.states[SCAN_SYN], "open") == 0) return "Open";
        if (strcmp(res.states[SCAN_SYN], "filtered") == 0) return "Filtered";
    }

    if ((res.states[SCAN_NULL] && strcmp(res.states[SCAN_NULL], "closed") == 0) ||
        (res.states[SCAN_FIN] && strcmp(res.states[SCAN_FIN], "closed") == 0) ||
        (res.states[SCAN_XMAS] && strcmp(res.states[SCAN_XMAS], "closed") == 0)) {
        return "Closed";
    }

    if (res.states[SCAN_ACK] && strcmp(res.states[SCAN_ACK], "unfiltered") == 0) {
        return "Unfiltered";
    }

    return "Open|Filtered";
}

const char *get_reason(t_port_result res) {
    if (res.states[SCAN_SYN]) {
        if (strcmp(res.states[SCAN_SYN], "open") == 0) return "syn-ack";
        if (strcmp(res.states[SCAN_SYN], "filtered") == 0) return "no-response";
    }

    if ((res.states[SCAN_NULL] && strcmp(res.states[SCAN_NULL], "closed") == 0) ||
        (res.states[SCAN_FIN] && strcmp(res.states[SCAN_FIN], "closed") == 0)) {
        return "rst";
    }

    if (res.states[SCAN_ACK] && strcmp(res.states[SCAN_ACK], "unfiltered") == 0) {
        return "rst";
    }

    return "no-response";
}

static void print_table_header(void) {
    printf("%-8s %-20s %-30s %-15s", "Port", "Service", "Results", "Conclusion");
    #ifdef BONUS
    if (get_option(OPT_REASON)->value) printf(" %-10s", "Reason");
    #endif
    printf("\n------------------------------------------------------------------------------------------\n");
}

static void print_port_row(t_port_result res)
{
    struct servent *serv = getservbyport(htons(res.port), "tcp");
    char *serv_name = serv ? serv->s_name : "Unassigned";

    printf("%-8d %-20s ", res.port, serv_name);

    int col_count = 0;
    for (int scan = 0; scan < SCAN_COUNT; scan++) {
        if (res.states[scan]) {
            printf("%s(%s) ", scan_to_string(scan), res.states[scan]);
            col_count++;
            if (col_count % 2 == 0 && col_count < SCAN_COUNT) {
                printf("\n%-30s", "");
            }
        }
    }
    printf("%-15s ", get_conclusion(res));
    #ifdef BONUS
        if (get_option(OPT_REASON)->value) printf("%-10s", get_reason(res));
    #endif
    printf("\n");
}

void print_final_results(t_port_result *results, size_t port_count, struct in_addr target_ip)
{
    printf("\nIP address: %s\n", to_str(target_ip));
    (void) port_count;
    (void) results;
    
    printf("Open ports:\n");
    print_table_header();
    for (size_t i = 0; i < port_count; i++) {
        if (!results[i].is_scanned) continue;
        if (is_any_scan_open(results[i]))
            print_port_row(results[i]);
    }

    if (get_option(OPT_OPEN)->value) return ;
    printf("\nClosed/Filtered/Unfiltered ports:\n");
    print_table_header();
    for (size_t i = 0; i < port_count; i++) {
        if (!results[i].is_scanned) continue;
        if (!is_any_scan_open(results[i]))
            print_port_row(results[i]);
    }
}
