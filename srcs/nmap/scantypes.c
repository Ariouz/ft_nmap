# include "ft_nmap.h"

static void	free_split(char **split, int len)
{
	int	i;

	i = 0;
	while (i < len)
		free(split[i++]);
	free(split);
}

void	parse_types(char *input)
{
	char	**split_types;
	int		len;
	int		i;

	if (!input || !*input) {
        g_opts->scans[SCAN_SYN] = 1;
        g_opts->scans[SCAN_NULL] = 1;
        g_opts->scans[SCAN_ACK] = 1;
        g_opts->scans[SCAN_FIN] = 1;
        g_opts->scans[SCAN_XMAS] = 1;
        g_opts->scans[SCAN_UDP] = 1;
        return ;
    }

	bzero(g_opts->scans, sizeof(g_opts->scans));

	split_types = NULL;
	len = split(input, ',', &split_types);
	if (len <= 0)
		fatal_error("Invalid scan types.");

	i = 0;
	while (i < len)
	{
		if (!*split_types[i])
			break ;
		if (!strcmp(split_types[i], "SYN"))
		{
			if (g_opts->scans[SCAN_SYN])
				break ;
			g_opts->scans[SCAN_SYN] = 1;
		}
		else if (!strcmp(split_types[i], "NULL"))
		{
			if (g_opts->scans[SCAN_NULL])
				break ;
			g_opts->scans[SCAN_NULL] = 1;
		}
		else if (!strcmp(split_types[i], "ACK"))
		{
			if (g_opts->scans[SCAN_ACK])
				break ;
			g_opts->scans[SCAN_ACK] = 1;
		}
		else if (!strcmp(split_types[i], "FIN"))
		{
			if (g_opts->scans[SCAN_FIN])
				break ;
			g_opts->scans[SCAN_FIN] = 1;
		}
		else if (!strcmp(split_types[i], "XMAS"))
		{
			if (g_opts->scans[SCAN_XMAS])
				break ;
			g_opts->scans[SCAN_XMAS] = 1;
		}
		else if (!strcmp(split_types[i], "UDP"))
		{
			if (g_opts->scans[SCAN_UDP])
				break ;
			g_opts->scans[SCAN_UDP] = 1;
		}
		else
			break ;
		i++;
	}
	free_split(split_types, len);

	if (i != len)
		fatal_error("Invalid scan types.");
}