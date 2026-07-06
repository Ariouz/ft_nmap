# include "ft_nmap.h"


t_option    *get_option(int code)
{
    size_t      index;
    index = 0;

    while (index < g_opts->size)
    {
        if (code == g_opts->options[index]->code)
            return g_opts->options[index];
        index++;
    }

    return NULL;
}

void print_help()
{
    printf("Usage: ft_nmap [options] <destination>\nOptions:\n");

    printf("\t --help\t\t\tDisplay this help list\n");

    # ifdef BONUS
    size_t  index = 0;
    while (index < g_opts->size) {
        t_option *opt = g_opts->options[index];

        printf("\t -%c", opt->code);
        if (opt->requires_value) printf(" <value>");
        printf("\t\t\t%s\n", opt->description);

        index++;
    }
    # endif

    clean_free(g_opts);
    exit(0);
}