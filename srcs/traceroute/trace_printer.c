#include "ft_nmap.h"

static void print_hostname_and_ip(struct in_addr addr)
{
    struct hostent *host = gethostbyaddr(&addr, sizeof(addr), AF_INET);
    (void) host;

    char *ip_str = inet_ntoa(addr);

    # ifdef BONUS
    if (get_option(OPT_NO_DNS)->value == true)
        printf("%s", ip_str);
    else if (host && host->h_name)
        printf("%s (%s)", host->h_name, ip_str);
    else
        printf("%s (%s)", ip_str, ip_str);
    # else 
        printf("%s (%s)", ip_str, ip_str);
    # endif
}

static int has_responded(float rtts[3]) {
    for (int i = 0; i < 3; i++) {
        if (rtts[i] >= 0.0f)
            return 1;
    }
    return 0;
}

static int get_first_valid_index(float rtts[3]) {
    for (int i = 0; i < 3; i++) {
        if (rtts[i] >= 0.0f)
            return i;
    }
    return -1;
}

static int all_same_responders(struct in_addr addrs[3], float rtts[3], int first_valid_index) {
    for (int i = first_valid_index + 1; i < 3; i++) {
        if (rtts[i] >= 0.0f && addrs[i].s_addr != addrs[first_valid_index].s_addr)
            return 0;
    }
    return 1;
}

static void fill_addrs_and_rtts(t_requests requests[3], struct in_addr addrs[3], float rtts[3]) {
    for (int i = 0; i < 3; i++) {
        if (requests[i].rtt >= 0.0f) {
            addrs[i] = requests[i].responder.sin_addr;
            rtts[i] = requests[i].rtt;
        } else {
            addrs[i].s_addr = 0;
            rtts[i] = -1.0f;
        }
    }
}

static void print_all_same_line(struct in_addr addr, float rtts[3]) {
    print_hostname_and_ip(addr);
    printf("  ");
    for (int i = 0; i < 3; i++) {
        if (rtts[i] < 0.0f)
            printf("*  ");
        else
            printf("%.3f ms  ", rtts[i]);
    }
    printf("\n");
}

static void print_mixed_responders(struct in_addr addrs[3], float rtts[3]) {
    struct in_addr last_addr = {0};
    int first = 1;

    for (int i = 0; i < 3; i++) {
        if (rtts[i] < 0.0f)
            printf("*  ");
        else {
            if (first || addrs[i].s_addr != last_addr.s_addr) {
                print_hostname_and_ip(addrs[i]);
                last_addr = addrs[i];
                first = 0;
            }
            printf("  %.3f ms  ", rtts[i]);
        }
    }
    printf("\n");
}


void process_results(int ttl, struct s_requests requests[3]) {
    struct in_addr addrs[3];
    float rtts[3];

    fill_addrs_and_rtts(requests, addrs, rtts);

    int responded = has_responded(rtts);
    printf("%2d  ", ttl);

    if (!responded) {
        printf("* * *\n");
        return;
    }

    int first_valid_index = get_first_valid_index(rtts);
    int all_same = all_same_responders(addrs, rtts, first_valid_index);

    if (all_same)
        print_all_same_line(addrs[first_valid_index], rtts);
    else
        print_mixed_responders(addrs, rtts);
}