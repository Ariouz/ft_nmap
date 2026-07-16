# include "ft_nmap.h"

int def_value(int code) {
    switch (code) {
        case OPT_SOURCE_PORT: return 42424; break;
        case OPT_TTL: return DEFAULT_TTL; break;
        case OPT_OPEN: return false; break;
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

t_option *get_option(int code) {
    for (size_t i = 0; i < g_opts->size; i++) {
        if (g_opts->options[i]->code == code) return g_opts->options[i];
    }
    
    // defaults
    for (size_t i = 0; i < g_opts->def_size; i++) {
        if (g_opts->def_options[i]->code == code) return g_opts->def_options[i];
    }
    
    return NULL;
}