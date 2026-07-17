## Transition: traceroute -> nmap
- [X] Packet type: PING -> SYN, NULL, ACK, FIN, XMAS, UDP 
- [X] TTL loop: port loop (range) (1-1024) max range len 1024
- [X] Threads: thread pool / semaphore, 0-250 (0 default)
- [X] Responses: wait_socket -> pcap (we don't 'wait' for a response anymore)
- [X] Output: traceroute output -> nmap style output
- [X] Service TYPE resolution
- [~] Terminer les // todo

## Bonuses
- [X] Bonus: --ttl
- [X] Bonus: -g/--source-port
- [X] Bonus: --open (show only open results)
- [X] Bonus: --badsum
- [X] Bonus: -n / --no-dns
- [X] Bonus: --reason