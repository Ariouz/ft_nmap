# include "ft_nmap.h"

int split(char *str, char c, char ***arr) {
    int count = 1;
    char *p = str;
    
    while (*p) if (*p++ == c) count++;
    
    *arr = (char **)malloc(sizeof(char *) * (count + 1));
    if (!*arr) return -1;
    (*arr)[count] = NULL;

    int i = 0;
    char *start = str;
    char *end;
    while (i < count) {
        end = strchr(start, c);
        size_t len = end ? (size_t)(end - start) : strlen(start);
        
        (*arr)[i] = (char *)malloc(len + 1);
        if (!(*arr)[i]) return -1;
        
        strncpy((*arr)[i], start, len);
        (*arr)[i][len] = '\0';
        
        if (!end) break;
        start = end + 1;
        i++;
    }
    return count;
}