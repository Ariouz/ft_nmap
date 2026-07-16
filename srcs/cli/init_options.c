#include "ft_nmap.h"

void    init_opts()
{
    g_opts = (t_opts *) malloc(sizeof(t_opts));
    if (!g_opts)
        return ;
    
    g_opts->options = malloc(sizeof(t_option *) * MAX_OPTS);
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
    
}

void init_default_options() {
    g_opts->def_size = 2;
    g_opts->def_options = malloc(sizeof(t_option *) * g_opts->def_size);
    
    g_opts->def_options[0] = get_default_if_not_opt(OPT_SOURCE_PORT);
    g_opts->def_options[1] = get_default_if_not_opt(OPT_TTL);
}

void    init_cli_options()
{
    init_opts();
    init_default_options();
    if (!g_opts || !g_opts->options)
        fatal_error("Fatal: Failed to init CLI options");

    // add_option(OPT_FIRST_TTL, "First TTL (default 1)", 1, false);
    // add_option(OPT_MAX_TTL, "Max TTL (default 30)", 30, false);
    // add_option(OPT_NO_DNS, "Disables DNS resolution", false, false);
    // add_option(OPT_PORT, "The base UDP packet port (default 33434)", 33434, false);
    // add_option(OPT_SOCK_TIMEOUT, "Max time (in seconds) to wait for a probe (default 1)", 1, false);
    #ifdef BONUS
    add_option(OPT_SOURCE_PORT, "Source port (default 42424)", 42424, true);
    add_option(OPT_TTL, "Packet TTL", DEFAULT_TTL, true);
    #endif

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
