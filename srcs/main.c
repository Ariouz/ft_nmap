#include "ft_nmap.h"

t_opts *g_opts = NULL;

int main(int argc, char **argv)
{
	init_cli_options(argc, argv);
	parse_cli_options(argc, argv);

	int args_count = argc - optind;

	if (args_count < 1)
		fatal_error("Destination IP/hostname required");
	if (args_count > 1)
		fatal_error("Destination already set or unknown flag");

	g_opts->hostname = argv[optind];
	g_opts->target_ip = resolve_ip(argv[optind]);

	if (g_opts->target_ip.s_addr == INADDR_NONE)
		fatal_error("Unknown host");

	handle_signals();

	parse_types(NULL); // hardcoded NULL

	trace();
	clean_exit(0);
	return (0);
}
