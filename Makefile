dhcp-stats : dhcp-stats.c
	gcc -o dhcp-stats dhcp-stats.c -lm -lpcap -lncurses -Werror -Wextra