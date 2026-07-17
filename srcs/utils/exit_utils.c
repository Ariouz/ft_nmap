#include "ft_nmap.h"

void    clean_free()
{
    if (!g_opts) return;

    if (g_opts->ports) free(g_opts->ports);
    if (g_opts->targets) free(g_opts->targets);
    free_options(g_opts->options, g_opts->size);
    if (g_opts->def_options) free_options(g_opts->def_options, g_opts->def_size);
    free(g_opts);
}

void    free_options(t_option **options, size_t opt_len)
{
    size_t  index = 0;
    if (!options) return ;

    while (index < opt_len)
    {
        if (options[index]) free(options[index]);
        index++;
    }
    free(options);
}

void    clean_exit(int exit_code)
{
    if (g_opts)
    {
        if (g_opts->sockfd_icmp != -1) close(g_opts->sockfd_icmp);
        if (g_opts->sockfd_udp != -1) close(g_opts->sockfd_udp);
		clean_free();
    }
    exit(exit_code);
}
