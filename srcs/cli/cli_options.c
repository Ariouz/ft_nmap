# include "ft_nmap.h"

int def_value(int code) {
    switch (code) {
        case OPT_SOURCE_PORT: return 42424; break;
        case OPT_TTL: return DEFAULT_TTL; break;
        default: return 0; break;
    }
    return 0;
}

t_option    *get_default_if_not_opt(int code) {
    t_option *def = malloc(sizeof(t_option));
    if (!def) return NULL;

    def->code = code;
    def->description = "Default";
    def->requires_value = false;
    def->value = def_value(code);
    return def;
}

t_option    *get_option(int code)
{
    size_t      index;
    index = 0;

    t_option    *res = NULL;

    while (index < g_opts->size)
    {
        if (code == g_opts->options[index]->code) {
            res = g_opts->options[index];
            break ;
        }
        index++;
    }

    if (!res) return get_default_if_not_opt(code);
    return res;
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