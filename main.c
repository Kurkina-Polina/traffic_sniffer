#include<stdio.h>
#include <stdlib.h>
#include<malloc.h>
#include<string.h>
#include<signal.h>
#include<stdbool.h>
#include <poll.h>

#include<sys/socket.h>
#include<sys/types.h>
#include <unistd.h>
#include<linux/if_packet.h>

#include<netinet/in.h>         
#include<netinet/if_ether.h>      
#include<netinet/ip.h>            
#include<netinet/udp.h>           
#include<netinet/tcp.h>           
#include<arpa/inet.h>   
#include <errno.h>
#include <stdint.h>       // Для uintX_t типов
#include <netinet/in.h>   // Для struct in_addr
#include <net/ethernet.h> // Для ether_addr


#define MAX_PORTS 65536
#define MAX_MESSAGE 1000

#define DPRINTF(...) printf(__VA_ARGS__)

static volatile int keepRunning = 1;
int is_already_established = 0;

struct filter_flag{
    int vlan_id_flag;
    int dst_MAC_flag;
    int src_MAC_flag;
    int ether_type_flag;
    int dst_IPv4_flag;
    int src_IPv4_flag;
    int dst_IPv6_flag;
    int src_IPv6_flag;
    int IP_protocol_flag;
    int dst_TCP_flag;
    int src_TCP_flag;
    int dst_UDP_flag;
    int src_UDP_flag;
};

struct filter{
    uint16_t vlan_id;
    struct ether_addr dst_MAC;
    struct ether_addr src_MAC;
    uint16_t ether_type;
    struct in_addr dst_IPv4;
    struct in_addr src_IPv4;
    struct in6_addr dst_IPv6;
    struct in6_addr src_IPv6;
    uint8_t IP_protocol;
    uint16_t dst_TCP;
    uint16_t src_TCP;
    u_short dst_UDP;
    u_short src_UDP;

    size_t count_packets;
    size_t size;
    struct filter_flag flags;
   
};


void print_mac_addr(uint8_t const* const addr) {
    printf("%d:%d:%d:%d:%d:%d \n", addr[0], addr[1], addr[2],addr[3],addr[4],addr[5]);
}

void handler(){
    keepRunning = 0;
}


void  tcp_header(char* buffer, int buflen, int iphdrlen){
    struct tcphdr *tcp = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
    printf("TCP Header \n");
    printf("Source TCP         : %u\n", ntohs(tcp->th_sport));
    printf("Destination TCP    : %u\n", ntohs(tcp->th_dport));
    printf("\n\n ");

}

void ip_header(char* buffer, int buflen){
    struct ip const* const ip_head = (struct ip const*)(buffer + sizeof(struct ether_header));
    printf("IP Header \n");
    printf("Version %u\n", ip_head->ip_v);
    printf("header length %u\n", ip_head->ip_hl);
    printf("Type of service. %u\n", ip_head->ip_tos);
    printf("protocol %u\n", ip_head->ip_p);
    printf("Source IP         : %s\n", inet_ntoa(ip_head->ip_src));
    printf("Destination IP    : %s\n",inet_ntoa(ip_head->ip_dst));
    

    if (ip_head->ip_p == 6){
        tcp_header(buffer, buflen, ip_head->ip_hl);
    }
    else{
        printf("\n\n ");
    }
}

int check_vlan(char* buffer, int buflen, uint16_t vlan_id){
    return 1;
}
int check_mac(char* buffer, int buflen, struct ether_addr MAC){
    return 1;
}
int check_ether_type(char* buffer, int buflen, uint16_t ether_type){
    return 1;
}
int check_IPv4(char* buffer, int buflen,  struct in_addr IPv){
    return 1;
}
int check_IPv6(char* buffer, int buflen, struct in6_addr IPv6){
    return 1;
}
int check_IP_protocol(char* buffer, int buflen, uint8_t IP_protocol){
    return 1;
}
int check_TCP(char* buffer, int buflen, uint16_t TCP){
    return 1;
}
int check_UDP(char* buffer, int buflen, u_short UDP){
    return 1;
}

// обрабатывает пакет, если проходит по фильтрам, то добавляем к собираемой статистике
void data_process(char* buffer, int buflen, struct filter* filters, int filters_len){
    for (int i=0; i<filters_len; i++){
        int is_suitable = 1;

        if(filters[i].flags.vlan_id_flag){
            is_suitable *= check_vlan(buffer, buflen, filters[i].vlan_id);
        }
        else{
            DPRINTF("Hello %d", 42);
        }
        if(filters[i].flags.dst_MAC_flag){
            is_suitable *= check_mac(buffer, buflen, filters[i].dst_MAC);
        }
        
        if(filters[i].flags.src_MAC_flag){
            is_suitable *= check_mac(buffer, buflen, filters[i].src_MAC);
        }
        if(filters[i].flags.ether_type_flag){
            is_suitable *=  check_ether_type(buffer, buflen, filters[i].ether_type);
        }
        if(filters[i].flags.dst_IPv4_flag){
            is_suitable *= check_IPv4(buffer, buflen, filters[i].dst_IPv4);
        }
        if(filters[i].flags.src_IPv4_flag){
            is_suitable *= check_IPv4(buffer, buflen, filters[i].src_IPv4);
        }
        if(filters[i].flags.dst_IPv6_flag){
            is_suitable *= check_IPv6(buffer, buflen, filters[i].dst_IPv6);
        }
        if(filters[i].flags.src_IPv6_flag){
            is_suitable *= check_IPv6(buffer, buflen, filters[i].src_IPv6);
        }
        if(filters[i].flags.IP_protocol_flag){
            is_suitable *= check_IP_protocol(buffer, buflen, filters[i].IP_protocol);
        }
        if(filters[i].flags.dst_TCP_flag){
            is_suitable *= check_TCP(buffer, buflen, filters[i].dst_TCP);
        }
        if(filters[i].flags.src_TCP_flag){
            is_suitable *= check_TCP(buffer, buflen, filters[i].src_TCP);
        }
        if(filters[i].flags.dst_UDP_flag){
            is_suitable *= check_UDP(buffer, buflen, filters[i].dst_UDP);
        }
        if(filters[i].flags.src_UDP_flag){
            is_suitable *= check_UDP(buffer, buflen, filters[i].src_UDP);
        }

        if(is_suitable){
            filters[i].count_packets += 1;
            filters[i].size += buflen;
        }
    }


    // printf("Ethernet Header \n");
    // struct ether_header const* const ether = (struct ether_header const*)buffer;
    // printf("dest Mac ");
    // print_mac_addr(ether->ether_dhost);
    // printf("sourse Mac ");
    // print_mac_addr(ether->ether_shost);

    // printf("Ether type %u\n", ether->ether_type);

    // if (ether->ether_type == 8){
    //     ip_header(buffer, buflen);
    // }
    
}

char const* get_statistics(struct filter* filters,  int filters_len){
    return "success";
}

char* const add_filter(char* buff, struct filter* filters, int filters_len){
    return "success";
}

char* const delete_filter(char* buff, struct filter* filters,  int filters_len){
    return "success";
}

void input_from_client(int connfd, struct filter* filters,  int filters_len){
    char buff[MAX_MESSAGE] = {};   

    // read the message from client and copy it in buffer 
    read(connfd, buff, sizeof(buff)); 
    // print buffer which contains the client contents 
    printf("From client: %s\t", buff); 

    if (strncmp("add filter", buff,  10) == 0){
        char const* message = add_filter(buff, filters, filters_len);
        memset(buff, 0, sizeof(buff));
        strncpy(buff, message, sizeof(message));
    }

    if (strncmp( "delete filter", buff, 13) == 0){
        char const* message = delete_filter(buff, filters, filters_len);
        memset(buff, 0, sizeof(buff));
        strncpy(buff, message, sizeof(message));
    }

    if (strncmp("print", buff,  5) == 0){ 
        char const*  message  = get_statistics(filters, filters_len);
        memset(buff, 0, sizeof(buff));
        strncpy(buff, message, sizeof(message));
    }
    write(connfd, buff, sizeof(buff)); 
        
}



int main(int argc, char* argv[]){
    signal(SIGINT, handler);
    int  sock_r, connfd, sock_listen, saddr_len, buflen;
    int filters_len = 0;
    struct sockaddr saddr;
    int max_filters = 10; // как аргумент при запуске должен быть

    unsigned char* buffer = (unsigned char *)malloc(MAX_PORTS); 
    memset(buffer,0,MAX_PORTS);

    printf("starting .... \n");

    // Open raw socket on Ethernet layer.
    sock_r = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL)); 
    sock_listen = socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0);
    if(sock_r<0 && sock_listen<0)
    {
        perror("error in socket\n");
        return -1;
    }

    // assign IP, PORT 
    int port = 8080;
    struct sockaddr_in servaddr, clientaddr; 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    servaddr.sin_port = htons(port); 
    
  
    // Binding newly created socket to given IP and verification 
    if ((bind(sock_listen, (struct sockaddr*)&servaddr, sizeof(servaddr))) != 0) { 
        printf("socket bind failed...\n"); 
        exit(0); 
    } 
    if ((listen(sock_listen, 5)) != 0) { 
        printf("Listen failed...\n"); 
        exit(0); 
    } 

    // creating poll
    nfds_t count_sockets = 3;
    struct pollfd fds[count_sockets];
    fds[0].fd = sock_r;
    fds[0].events = POLL_IN;
    fds[1].fd = sock_listen;
    fds[1].events = POLL_IN;

    struct filter* filters = (struct filter *)malloc(sizeof(struct filter) * max_filters); 

    
    while(keepRunning)
    {
        int count_poll = poll(fds,  count_sockets, -1);
        if (count_poll == -1){
            perror("poll error");
            exit(0);
        }

        if(fds[0].revents & POLL_IN){
            
            saddr_len = sizeof saddr;
            buflen = read(sock_r,buffer, MAX_PORTS);

            if(buflen<0)
            {
                printf("error in reading recvfrom function\n");
                return -1;
            }
            data_process(buffer, buflen, filters,  filters_len);
        }
        
        if(fds[1].revents & POLL_IN){
            // подключаемся к серверу
            printf("server read signal to connect\nw");
            socklen_t connfd_len;
            connfd = accept(sock_listen, (struct sockaddr*)&clientaddr, &connfd_len);
            if (is_already_established) {
                char message[] = "Already busy";
                memmove(buffer, message, sizeof(message));
                write(connfd, buffer, sizeof(buffer)); 
                close(connfd);
                continue;
            }
            fds[2].fd = connfd;
            fds[2].events = POLL_IN;
            is_already_established = 1;
        }
        if(fds[2].revents & POLL_IN){
            input_from_client(connfd, filters, filters_len);
        }



    }

    
    close(sock_r);
    printf("DONE!!!!\n");
}