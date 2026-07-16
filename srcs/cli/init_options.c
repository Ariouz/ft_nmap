#include "ft_nmap.h"

void    init_opts()
{
    g_opts = calloc(1, sizeof(*g_opts));
    if (!g_opts)
        return ;
    
    g_opts->options = calloc(MAX_OPTS, sizeof(*g_opts->options));
    if (!g_opts->options)
        return ;

    g_opts->size = 0;
    g_opts->is_running = true;
    g_opts->sockfd_icmp = -1;
    g_opts->sockfd_udp = -1;
    g_opts->ports = NULL;
    g_opts->port_count = 0;
    g_opts->targets = NULL;
    g_opts->target_count = 0;
	parse_types(NULL); // default scans
}

void init_default_options() {
    g_opts->def_size = 4;
    g_opts->def_options = calloc(g_opts->def_size, sizeof(*g_opts->def_options));
    if (!g_opts->def_options)
        fatal_error("Fatal: Failed to initialize default options");
    
    g_opts->def_options[0] = get_default_if_not_opt(OPT_SOURCE_PORT);
    g_opts->def_options[1] = get_default_if_not_opt(OPT_TTL);
    g_opts->def_options[2] = get_default_if_not_opt(OPT_OPEN);
    g_opts->def_options[3] = get_default_if_not_opt(OPT_REASON);
}

void    init_cli_options()
{
    init_opts();
    if (!g_opts || !g_opts->options)
        fatal_error("Fatal: Failed to init CLI options");
    init_default_options();

    #ifdef BONUS
    add_option(OPT_SOURCE_PORT, "Source port (default 42424)", 42424, true);
    add_option(OPT_TTL, "Packet TTL", DEFAULT_TTL, true);
    add_option(OPT_OPEN, "Display only open ports", false, false);
    add_option(OPT_REASON, "Display the reason a port is in state", false, false);
    #endif
    add_option(OPT_SPEEDUP, "Number of parallel threads (default 0, max 250)", 0, true);

}

void        add_option(int code, char *description, int default_value, bool requires_value)
{
    t_option   *option;

    option = create_option(code, description, default_value, requires_value);
    if (!option)
    {
        fatal_error("Fatal: Failed to create CLI option");
        return ;
    }
    save_option(option);
}

void        save_option(t_option *option)
{
    if (g_opts->size >= MAX_OPTS) return ;
    g_opts->options[g_opts->size] = option;
    g_opts->size++;
}

t_option    *create_option(int code, char *description, int default_value, bool requires_value)
{
    t_option *option;
    option = (t_option *) malloc(sizeof(t_option));
    if (!option)
        fatal_error("Failed to init cli option");

    option->code = code;
    option->description = description;
    option->value = default_value;
    option->requires_value = requires_value;

    return option;
}
