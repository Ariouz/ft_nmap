#include "ft_nmap.h"

void add_target(const char *ip) {
    struct in_addr resolved_ip = resolve_ip(ip);
    struct in_addr *targets;

    if (resolved_ip.s_addr == INADDR_NONE) {
        char s[256];
        sprintf(s, "Invalid address: %s", ip);
        fatal_error(s);
    }
    targets = realloc(g_opts->targets,
            sizeof(struct in_addr) * (g_opts->target_count + 1));
    if (!targets)
        fatal_error("Memory allocation failed");
    g_opts->targets = targets;
    g_opts->targets[g_opts->target_count] = resolved_ip;
    g_opts->target_count++;
}

void parse_file(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        char s[256];
        sprintf(s, "Could not open file: %s", filename);
        fatal_error(s);
    }
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = 0;
        if (strlen(line) > 0)
            add_target(line);
    }
    fclose(fp);
}
