#include "ft_nmap.h"

void    handle_sig_int(int code)
{
    (void) code;
    
    g_opts->is_running = false;
}

void handle_signals()
{
    if (signal(SIGINT, handle_sig_int) == SIG_ERR)
        fatal_error("Failed to register sigint handler");
}