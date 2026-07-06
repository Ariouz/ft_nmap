#include "ft_nmap.h"

bool    is_runnning()
{
    bool run;

    run = g_opts->is_running;
    return run;
}

void    clean_free()
{
    if (!g_opts) return;

    free_options(g_opts->options, g_opts->size);
    free(g_opts);
}

void    free_options(t_option **options, size_t opt_len)
{
    size_t  index = 0;
    if (!options) return ;

    while (index < opt_len)
    {
        free(options[index]);
        index++;
    }
    free(options);
}

void    clean_exit(int exit_code)
{
    if (g_opts->sockfd_icmp != -1) close(g_opts->sockfd_icmp);
    if (g_opts->sockfd_udp != -1) close(g_opts->sockfd_udp);
	clean_free();
    exit(exit_code);
}