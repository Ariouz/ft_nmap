#include "ft_nmap.h"

void    exit_error()
{
    clean_exit(1);
}

void    fatal_error(char *msg)
{
    printf("Error: %s\n", msg);
    exit_error();
}
