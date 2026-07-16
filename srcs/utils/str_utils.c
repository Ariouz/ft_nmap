# include "ft_nmap.h"

int split(char *str, char c, char ***arr) {
    if (!str) return 0;
    
    int count = 0;
    char *p = str;
    
    while (*p) {
        if (*p != c && (p == str || *(p - 1) == c))
            count++;
        p++;
    }
    
    *arr = (char **)calloc(count + 1, sizeof(char *));
    if (!*arr) return -1;

    int i = 0;
    char *start = str;
    while (*start) {
        if (*start == c) {
            start++;
            continue;
        }
        char *end = strchr(start, c);
        size_t len = end ? (size_t)(end - start) : strlen(start);
        
        (*arr)[i] = strndup(start, len);
        i++;
        start += len;
    }
    return i;
}