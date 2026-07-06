#include "ft_nmap.h"

long long get_time_ms(struct timeval tv) {
    return (long long)(tv.tv_sec) * 1000 + (long long)(tv.tv_usec) / 1000;
}

long long get_time_us(struct timeval tv) {
    return (long long)(tv.tv_sec) * (1000*1000) + (long long)(tv.tv_usec);
}

int		multisleep(long max_time_millis, long increment)
{
	long total_time_millis;

	total_time_millis = 0;
	while (total_time_millis < max_time_millis)
	{
		total_time_millis += increment;
		usleep(increment * 1000);
		if (!g_opts->is_running)
		{
			return -1;
		}
	}
	return 0;
}