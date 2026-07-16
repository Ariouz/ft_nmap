#include "ft_nmap.h"

t_opts *g_opts = NULL;

int main(int argc, char **argv)
{
	init_cli_options(argc, argv);
	parse_cli_options(argc, argv);
	handle_signals();

	int args_count = argc - optind;
	(void) args_count;

	if (g_opts->port_count == 0) parse_port_option("1-1024");
	
	if (g_opts->target_count == 0)
		print_help();

	size_t	index = 0;
	while (index < g_opts->target_count) {
		printf("\n\n");
		trace(g_opts->targets[index]);
		index++;
	}
	clean_exit(0);
	return (0);
}
