SRCS= $(addprefix srcs/, \
	main.c \
	utils/ip_utils.c \
	utils/exit_utils.c \
	utils/error.c \
	utils/time_utils.c \
	utils/str_utils.c \
	cli/cli_options.c \
	cli/init_options.c \
	cli/cli_options_parser.c \
	cli/port_parser.c \
	socket/socket_send.c \
	socket/socket_receive.c \
	signals/sig_handler.c \
	nmap/tracer.c \
	nmap/trace_printer.c \
	nmap/scantypes.c \
	nmap/tcp_scan.c \
	nmap/udp_scan.c \
	)
OBJS= $(SRCS:.c=.o)

NAME= ft_nmap
FLAGS= -Wall -Werror -Wextra
INCLUDES= -Iincludes/
PCAP_LIB= -lpcap

all: $(NAME)

$(NAME): $(OBJS)
	@gcc $(FLAGS) $(OBJS) $(PCAP_LIB) -o $(NAME)

bonus: FLAGS += -DBONUS
bonus: fclean $(NAME)

%.o: %.c
	@gcc -c $< -o $@ $(FLAGS) $(INCLUDES)

clean:
	@rm -f $(OBJS)

fclean: clean
	@rm -f $(NAME)

re: fclean all
