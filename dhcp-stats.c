// ISA project - Monitorovani DHCP komunikace
// Vypracoval: Adam Kucik
// Login:      xkucik00

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <math.h>
#include <sys/socket.h>
#include <netinet/ether.h> 
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <signal.h>
#include <ncurses.h>
#include <syslog.h>

#define ETHERNET_HEADER (14)
#define MAX_IP_ADDR 100
#define LEN_IP_ADDR 16

/**
 * @struct ipaddr
 * @brief This struct has stored all needed data for work with each ip address
 * 
 * @param next Pointer that has stored list of ip addresses in subnet range
 * @param max_hosts Number of hosts
 * @param subnet Subnet
 * @param count Simple counter which increments when new address is added to list next
 * @param util Utilization counter
 * @param sys_flag Used for -i argument in utilization for logging to syslog just once for each ip address that exceeded
 */
struct ipaddr {
    struct ipaddr* next;
    char adress[LEN_IP_ADDR];
    int max_hosts;
    int subnet;
    int count;
    double util;
    int sys_flag;
};

/**
 * @brief Init function 
*/
struct ipaddr* init() {
    return NULL;
}

/**
 * @brief Function searchip prevents inserting same ip address in function insert
 * 
 * @return position or -1 if found nothing
*/
int searchip(struct ipaddr* head, char* data) {
    struct ipaddr* tmp = head;
    int pos = 0;

    while (tmp != NULL) {
        if (!strcmp(tmp->adress,data)) {
            return pos;
        }
        tmp = tmp->next;
        pos++;
    }
    return -1;
}

/**
 * @brief Inserts ip address to the list
 * 
 * @return Head of list
*/
struct ipaddr* insert(struct ipaddr* head, char* data, int* num) {
    *num = 0;
    if (searchip(head, data) != -1)
        return head;
    *num = 1;

    struct ipaddr* new = (struct ipaddr*)malloc(sizeof(struct ipaddr));
    if (new == NULL) {
        fprintf(stderr,"Malloc error!\n");
        exit(EXIT_FAILURE);
    }
        
    strcpy(new->adress,data);
    
    new->next = head;
    return new;
}

/**
 * @brief Prints all content of list. Used only for debugging
*/
void printList(struct ipaddr* head) {
    struct ipaddr* tmp = head;
    while (tmp != NULL) {
        printf("%s\n",tmp->adress);
        tmp = tmp->next;
    }
}

/**
 * @brief Free of list to free allocated memory 
*/
void freeList(struct ipaddr* head) {
    while (head != NULL) {
        struct ipaddr* tmp = head;
        head = head->next;
        free(tmp);
    }
}

/**
 * @brief Function for reversal of ip address
*/
void strrev(char *str) {
    int a,b,c,d;
    sscanf(str,"%d.%d.%d.%d",&a,&b,&c,&d);
    sprintf(str, "%d.%d.%d.%d",d,c,b,a);
}

/**
 * @brief Function checks if ip address is in subnet range
*/
int ipinrange(const char* ipAddr, const char* range, int prefix) {
    struct in_addr ip, net, mask;
    if (inet_pton(AF_INET, ipAddr, &ip) <= 0) {
        return 0;
    }
    if (inet_pton(AF_INET, range, &net) <= 0) {
        return 0;
    }

    mask.s_addr = htonl(((uint32_t)-1) << (32 - prefix));
    ip.s_addr &= mask.s_addr;
    net.s_addr &= mask.s_addr;

    return (ip.s_addr == net.s_addr);
}

volatile sig_atomic_t flag = 0;     // Used in -i argument to jump out of while cycle

/**
 * @brief Function used to handle SIGINT signal in -i argument
 */
void CtrlHandler(int signum) {
    flag = 1;
    endwin();
    exit(EXIT_SUCCESS);
}

/**
 * @brief Function used to log to the syslog
*/
void exceed_syslog(char* address, int subnet) {
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "Prefix %s/%d exceeded 50%% allocation", address, subnet);
    
    openlog("dhcp-stats", LOG_PID, LOG_USER);
    syslog(LOG_INFO, "%s" , buffer);
    closelog();
}

int main(int argc, char* argv[]) {
    //To avoid seg_fault without arguments
    if (argc == 1) {
        fprintf(stderr,"No argument selected use -r or -i with ip prefixes\n");
        return 0;
    }

    //for arg parse
    int arg_num = 1;    // 1 to skip name of program
    int r_id = 0;       // r_id for -r argument
    int i_id = 0;       // i_id for -i argument
    int sub_len;        // temporery variable to save subnet
    int max_hosts;      // temporery variable for maximum number of hosts
    int max_adress = argc - 1;
    char adression[LEN_IP_ADDR];    // temporary variable for ip address
    //pcap.h
    char errbuf[PCAP_ERRBUF_SIZE]; // defined in pcap.h
    char pcap_name[100];    
    int file_loc = 0;   // flag if pcap_close should be used
    // variables for work with packet
    pcap_t *handle;
    struct pcap_pkthdr header;
    const u_char *packet;
    struct ether_header *eptr;

    struct ipaddr ProgramAddress[argc-2];
    int IPAddress_i = 0;
    int ncurses_syslog = -1;    // variable for printing exceed information under statistics for -i argument

    // This while cycle is processing argument and saving them into variables
    // Then checking format of ip addresses and after that saving data about each ip address to ipaddr struct
    
    while(arg_num != argc) {
        if (!strcmp(argv[arg_num], "-i")) { // -i argument processing
            i_id = 1;
            
            if (argv[arg_num + 1] == NULL || argv[arg_num + 1][0] == '-') {
                fprintf(stderr, "After '-i' should be interaface!\n");
                exit(EXIT_FAILURE);
            }
            arg_num++;

            char inter_tmp[100];
            strcpy(inter_tmp, argv[arg_num]);

            int buff_size = 4 * 1024 * 1024;
            //ncurses initialization
            initscr();
            mvprintw(0,0,"IP-prefix MAX_hosts Allocated_addresses Utilization\n");
            refresh();

            handle = pcap_open_live(inter_tmp,buff_size,1,-1, NULL);

            if (handle == NULL) {
                fprintf(stderr, "Error during opening of eth0!\n");
                exit(EXIT_FAILURE);
            }

        } else if (!strcmp(argv[arg_num], "-r")) {  // -r argument processing
            r_id = 1;
            if (argv[arg_num + 1] == NULL || argv[arg_num + 1][0] == '-') {
                fprintf(stderr, "Pcap file after '-r' is missing!\n");
                exit(EXIT_FAILURE);
            }

            arg_num++;
            char pcap_tmp[100];
            strcpy(pcap_name,argv[arg_num]);    //pcap name of file stored
            
            handle = pcap_open_offline(pcap_name, errbuf);
            if (handle == NULL) {
                fprintf(stderr, "Error during opening .pcap file\n");
                exit(EXIT_FAILURE);
            }
            file_loc = 1;
        } else {                                // ip addresses processing
            char adress_tmp[LEN_IP_ADDR];
            strcpy(adress_tmp,argv[arg_num]);
            char *adress_deter = strtok(adress_tmp,"/");
            strcpy(adression,adress_deter);

            if ((adress_deter = strtok(NULL, "/")) == NULL) {
                fprintf(stderr, "Subnet missing for IP adress!\n");
                exit(EXIT_FAILURE);
            }

            sub_len = atoi(adress_deter);
            max_hosts = pow(2,32 - sub_len) - 2;

            //sub_len check
            if (sub_len < 1 || sub_len > 31) {
                fprintf(stderr, "Wrong format of subnet should be number from 1 to 31!\n");
                exit(EXIT_FAILURE);
            }

            // checking format of ip address if x.x.x.x where x > 0 && 256 > x
            int adr_tmp_int;

            adress_deter = strtok(adress_tmp,".");
            adr_tmp_int = atoi(adress_deter);

            if (adr_tmp_int > 255 || adr_tmp_int < 0) {
                fprintf(stderr,"Wrong format of ip address!\n");
                exit(EXIT_FAILURE);
            }
            if ((adress_deter = strtok(NULL,".")) == NULL) {
                fprintf(stderr,"Wrong format of ip address!\n");
                exit(EXIT_FAILURE);
            }
            adr_tmp_int = atoi(adress_deter);

            if (adr_tmp_int > 255 || adr_tmp_int < 0) {
                fprintf(stderr,"Wrong format of ip address!\n");
                exit(EXIT_FAILURE);
            }
            if ((adress_deter = strtok(NULL,".")) == NULL) {
                fprintf(stderr,"Wrong format of ip address!\n");
                exit(EXIT_FAILURE);
            }
            adr_tmp_int = atoi(adress_deter);

            if (adr_tmp_int > 255 || adr_tmp_int < 0) {
                fprintf(stderr,"Wrong format of ip address!\n");
                exit(EXIT_FAILURE);
            }
            if ((adress_deter = strtok(NULL,".")) == NULL) {
                fprintf(stderr,"Wrong format of ip address!\n");
                exit(EXIT_FAILURE);
            }
            adr_tmp_int = atoi(adress_deter);

            if (adr_tmp_int > 255 || adr_tmp_int < 0) {
                fprintf(stderr,"Wrong format of ip address!\n");
                exit(EXIT_FAILURE);
            }
            if ((adress_deter = strtok(NULL,".")) != NULL) {
                fprintf(stderr,"Wrong format of ip address!\n");
                exit(EXIT_FAILURE);
            } 

            // transfering temporary variable into struct ipaddr
            strcpy(ProgramAddress[IPAddress_i].adress,adression);
            ProgramAddress[IPAddress_i].subnet = sub_len;
            ProgramAddress[IPAddress_i].max_hosts = max_hosts;
            ProgramAddress[IPAddress_i].count = 0;
            ProgramAddress[IPAddress_i].next = init();
            ProgramAddress[IPAddress_i].util = 0;
            ProgramAddress[IPAddress_i].sys_flag = 1;

            IPAddress_i += 1;
        }
        if (i_id == 1 && r_id == 1) {       // if both arguments are set which i consider as error 
            fprintf(stderr, "Error '-r' and '-i' in arguments! Only one option must be!\n");
            exit(EXIT_FAILURE);
        }
        arg_num++;
    }

    // This part of code is taken from Moodle: sniff.c, read-pcap.c from doc. Ing. Petr Matousek Ph.D, M.A.
    if (i_id == 1) {
        signal(SIGINT, CtrlHandler);    // handle of SIGINT
        while (!flag) {
            while ((packet = pcap_next(handle,&header)) != NULL) {  //Going through each packet
                eptr = (struct ether_header *) packet;
                if (ntohs(eptr->ether_type) == ETHERTYPE_IP) {  // Checking if IPv4
                    const u_char *packet2 = packet + ETHERNET_HEADER;
                    u_int header_len;
                    struct ip* my_ip;

                    my_ip = (struct ip*) (packet2);
                    header_len = my_ip->ip_hl*4;        // compute IP4 header length
                    
                    if (my_ip->ip_p == IPPROTO_UDP) {           // Checking if UDP
                        const u_char *packet3 = packet2 + header_len;
                        const struct udphdr *my_udp;

                        my_udp = (const struct udphdr*) packet3;
                        if (ntohs(my_udp->source) == 67) {      // Checking port 67
                            int ind = 9;
                            const u_int8_t *dhcp_end = (const u_int8_t *)(packet3+ind); // This is meant to skip beggining from packet
                            int ind_cookie = -1;
                            while (*dhcp_end != 0xff) {     // Finding end of dhcp packet to find needed options
                                dhcp_end = (const u_int8_t *)(packet3+ind);
                                if (*dhcp_end == 0x01) {
                                    u_int8_t op_len = *(dhcp_end + 1);
                                    if (op_len == 0x04) {
                                        ind += 4;
                                    }
                                }
                                ind++;
                            }

                            int tmp_ind = 0;            // Finding magic_cookie
                            while (tmp_ind != ind) {
                                const u_int32_t *dhcp_cookie_tmp = (const u_int32_t *)(packet3 + tmp_ind * 4);
                                u_int32_t dhcp_val_tmp = ntohl(*dhcp_cookie_tmp);

                                if (dhcp_val_tmp == 0x63825363) {
                                    ind_cookie = tmp_ind;
                                }
                                tmp_ind++;
                            }

                            const u_int32_t *dhcp_cookie = (const u_int32_t *)(packet3+ind_cookie*4);

                            u_int32_t dhcp_val = ntohl(*dhcp_cookie);

                            if (dhcp_val == 0x63825363) {               // If i have magic cookie i am trying to find dhcp ack 
                                for (int k = ind_cookie; k < ind; k++ ) {
                                    const u_int8_t *dhcp_cookie2 = (const u_int8_t *)(packet3+k);
                                    u_int8_t dhcp_val = *dhcp_cookie2;
                                    if (dhcp_val == 0x05) {             // This value means that we have dhcp ack packet
                                        const u_int32_t *dhcp_address = (const u_int32_t *)(packet3+6*4);   // I am using offset which leads me to yiaddr
                                        u_int32_t dhcp_val = ntohl(*dhcp_address);
                                        struct in_addr ip_addr;
                                        ip_addr.s_addr = dhcp_val;

                                        char *ipaddr = inet_ntoa(ip_addr);  // This function gives me ip addres in reversal format
                                        strrev(ipaddr);                 // Reversing ipaddr to normal form as we are used
                                        
                                        int index = -1;
                                        for (int i = 0; i < IPAddress_i; i++) {     // Now i have everything from packet and i am saving it to ipaddr struct
                                            if (ipinrange(ipaddr, ProgramAddress[i].adress, ProgramAddress[i].subnet)) {
                                                index = i;
                                                int j = 0;
                                                ProgramAddress[i].next = insert(ProgramAddress[i].next,ipaddr,&j);
                                                ProgramAddress[i].count += j;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                for (int i = 0; i < IPAddress_i; i++) {     // Counting of utilization and printing through ncurses
                    ProgramAddress[i].util = ((double)ProgramAddress[i].count / (double)ProgramAddress[i].max_hosts) * 100;
                    mvprintw(i+1,0,"%s/%d %d %d %.2f%%\n", ProgramAddress[i].adress, ProgramAddress[i].subnet, ProgramAddress[i].max_hosts, ProgramAddress[i].count, ProgramAddress[i].util);

                    if (ProgramAddress[i].util > 50) {
                        if (ProgramAddress[i].sys_flag == 1) {      // Making sure to write to syslog once for each ip address if needed
                            exceed_syslog(ProgramAddress[i].adress, ProgramAddress[i].subnet);
                            ProgramAddress[i].sys_flag = 0;
                            ncurses_syslog++;
                            mvprintw(IPAddress_i+1+ncurses_syslog,0,"Prefix %s/%d exceeded 50%% allocation\n", ProgramAddress[i].adress, ProgramAddress[i].subnet);
                        }
                    }
                }
                refresh();
            }
        }   // This part of code is almost same as for i_id but for -r argument for reading pcap
    } else if (r_id == 1) {
        while ((packet = pcap_next(handle,&header)) != NULL) {
            eptr = (struct ether_header *) packet;
            if (ntohs(eptr->ether_type) == ETHERTYPE_IP) {
                const u_char *packet2 = packet + ETHERNET_HEADER;
                u_int header_len;
                struct ip* my_ip;

                my_ip = (struct ip*) (packet2);
                header_len = my_ip->ip_hl*4;
                
                if (my_ip->ip_p == IPPROTO_UDP) {
                    const u_char *packet3 = packet2 + header_len;
                    const struct udphdr *my_udp;
                    
                    my_udp = (const struct udphdr*) packet3;
                    if (ntohs(my_udp->source) == 67) {
                        int ind = 9;
                        const u_int8_t *dhcp_end = (const u_int8_t *)(packet3+ind);
                        int ind_cookie = -1;
                        while (*dhcp_end != 0xff) {
                            dhcp_end = (const u_int8_t *)(packet3+ind);
                            if (*dhcp_end == 0x01) {
                                u_int8_t op_len = *(dhcp_end + 1);
                                if (op_len == 0x04) {
                                    ind += 4;
                                }
                            }
                            ind++;
                        }

                        int tmp_ind = 0;
                        while (tmp_ind != ind) {
                            const u_int32_t *dhcp_cookie_tmp = (const u_int32_t *)(packet3 + tmp_ind * 4);
                            u_int32_t dhcp_val_tmp = ntohl(*dhcp_cookie_tmp);

                            if (dhcp_val_tmp == 0x63825363) {
                                ind_cookie = tmp_ind;
                            }
                            tmp_ind++;
                        }

                        const u_int32_t *dhcp_cookie = (const u_int32_t *)(packet3+ind_cookie*4);

                        u_int32_t dhcp_val = ntohl(*dhcp_cookie);

                        if (dhcp_val == 0x63825363) {
                            for (int k = ind_cookie; k < ind; k++ ) {
                                const u_int8_t *dhcp_cookie2 = (const u_int8_t *)(packet3+k);
                                u_int8_t dhcp_val = *dhcp_cookie2;
                                if (dhcp_val == 0x05) {
                                    const u_int32_t *dhcp_address = (const u_int32_t *)(packet3+6*4);
                                    u_int32_t dhcp_val = ntohl(*dhcp_address);
                                    struct in_addr ip_addr;
                                    ip_addr.s_addr = dhcp_val;

                                    char *ipaddr = inet_ntoa(ip_addr);
                                    strrev(ipaddr);
                                    
                                    int index = -1;
                                    for (int i = 0; i < IPAddress_i; i++) {
                                        if (ipinrange(ipaddr, ProgramAddress[i].adress, ProgramAddress[i].subnet)) {
                                            index = i;
                                            int j = 0;
                                            ProgramAddress[i].next = insert(ProgramAddress[i].next,ipaddr,&j);
                                            ProgramAddress[i].count += j;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    //Statistic to output for -r argument/ pcap file
    printf("IP-prefix MAX_hosts Allocated_addresses Utilization\n");
    for (int i = 0; i < IPAddress_i; i++) {
        ProgramAddress[i].util = ((double)ProgramAddress[i].count / (double)ProgramAddress[i].max_hosts) * 100;
        printf("%s/%d %d %d %.2f%%\n", ProgramAddress[i].adress, ProgramAddress[i].subnet, ProgramAddress[i].max_hosts, ProgramAddress[i].count, ProgramAddress[i].util);
    }

    for (int i = 0; i < IPAddress_i; i++) {
        if (ProgramAddress[i].util > 50) {
            printf("Prefix %s/%d exceeded 50%% allocation\n", ProgramAddress[i].adress, ProgramAddress[i].subnet);
            exceed_syslog(ProgramAddress[i].adress, ProgramAddress[i].subnet);
        }
        freeList(ProgramAddress[i].next);
    }
    
    if(file_loc == 1)
        pcap_close(handle);
    
    return 0;
}