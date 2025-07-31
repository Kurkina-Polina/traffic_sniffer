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
#define MAX_FILTERS 10

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
    unsigned short int dst_UDP;
    unsigned short int src_UDP;

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

void udp_header(char* buffer, int buflen, int iphdrlen){
    struct udphdr *udp = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
    printf("UDP Header \n");
    printf("Source UDP         : %u\n", udp->uh_sport);
    printf("Destination UDP    : %u\n", udp->uh_dport);
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
    else if(ip_head->ip_p == 17){
        udp_header(buffer, buflen, ip_head->ip_hl);
    }
    else{
        printf("\n\n ");
    }
}

int check_vlan(char* buffer, int buflen, uint16_t vlan_id){
    return 1;
}
int check_mac(char* buffer, int buflen, struct ether_addr MAC){
    struct ether_header const* const ether = (struct ether_header const*)buffer;
    uint8_t const* const addr = ether->ether_shost;
    for (int i =0; i<6; i++){
        if (MAC.ether_addr_octet[i]!=addr[i]){
            return 0;
        }
    }

    return 1;
}
int check_ether_type(char* buffer, int buflen, uint16_t ether_type){
    struct ether_header const* const ether = (struct ether_header const*)buffer;
    uint16_t ether_data = ether->ether_type;
    if(ether_data != ether_type){
        return 0;
    }
    return 1;
}
int check_IPv4(char* buffer, int buflen,  struct in_addr IPv, int is_scr){
    struct ether_header const* const ether = (struct ether_header const*)buffer;
    struct ip const* const ip_head = (struct ip const*)(buffer + sizeof(struct ether_header));
    if (ether->ether_type == 8){
        struct ip const* const ip_head = (struct ip const*)(buffer + sizeof(struct ether_header));
        if(is_scr){
            if(ip_head->ip_src.s_addr == IPv.s_addr){
                DPRINTF("it is %s=%s\n", inet_ntoa(ip_head->ip_src),  inet_ntoa(IPv));
                return 1;
            }
        }
        else{
            if(ip_head->ip_src.s_addr == IPv.s_addr){
                DPRINTF("it is %s=%s\n", inet_ntoa(ip_head->ip_src),  inet_ntoa(IPv));
                return 1;
            }
        }
       
    }
    else{
        DPRINTF("it is not ipv4\n");
        return 0;
    }
    return 0;
}
int check_IPv6(char* buffer, int buflen, struct in6_addr IPv6, int is_scr){
#if 0
    struct ether_header const* const ether = (struct ether_header const*)buffer;
    if (ether->ether_type == 0x86DD){
        struct in6_pktinfo const* const ip6_head = (struct in6_pktinfo const*)(buffer + sizeof(struct ether_header));
        if(is_scr){
            if(ip6_head->sin6_addr.s6_addr == IPv6.s6_addr){
                DPRINTF("it is %s=%s\n", inet_ntoa(ip_head->ip_src),  inet_ntoa(IPv6));
                return 1;
            }
        }
        else{
            if(ip6_head->sin6_addr.s6_addr == IPv6.s6_addr){
                DPRINTF("it is %s=%s\n", inet_ntoa(ip_head->ip_src),  inet_ntoa(IPv6));
                return 1;
            }
        }
    }
    else{
        DPRINTF("it is not ipv6\n");
        return 0;
    }
    return 1;
#else
    // TBD
    return 0;
#endif
}

int check_IP_protocol(char* buffer, int buflen, uint8_t IP_protocol){
    struct ether_header const* const ether = (struct ether_header const*)buffer;
    if (ether->ether_type == 8){
        struct ip const* const ip_head = (struct ip const*)(buffer + sizeof(struct ether_header));
        if( ip_head->ip_p == IP_protocol){
            DPRINTF("ip protocol is suitable%u\n", ip_head->ip_p);
            return 1;
        }
    }
    else if(ether->ether_type == 0x86DD){
        //TBD
        return 0;
    }
    return 0;
}
int check_TCP(char* buffer, int buflen, uint16_t TCP, int is_src){
    struct ether_header const* const ether = (struct ether_header const*)buffer;
    if (ether->ether_type == 8){
        struct ip const* const ip_head = (struct ip const*)(buffer + sizeof(struct ether_header));
        if (ip_head->ip_p == 6){
            struct tcphdr *tcp = (struct tcphdr*)(buffer + ip_head->ip_hl + sizeof(struct ethhdr));
            if (is_src && ntohs(tcp->th_sport) == TCP){
                DPRINTF("TCP is suitable%u\n", ntohs(tcp->th_sport));
                return 1;
            }
            else if( ntohs(tcp->th_dport) == TCP){
                DPRINTF("TCP is suitable%u\n",ntohs(tcp->th_dport));
                return 1;
            }
            else{
                DPRINTF("TCP not suit %u -> %u \n", ntohs(tcp->th_sport), ntohs(tcp->th_dport));
                
            }

        }
        else{
            //is not tcp
            return 0;
        }


    }
    else if(ether->ether_type == 0x86DD){
        //TBD
        return 0;
    }
    return 0;
}
int check_UDP(char* buffer, int buflen, unsigned short int UDP, int is_src){
    struct ether_header const* const ether = (struct ether_header const*)buffer;
    if (ether->ether_type == 8){
        struct ip const* const ip_head = (struct ip const*)(buffer + sizeof(struct ether_header));
        if (ip_head->ip_p == 17){

            struct udphdr *udp = (struct udphdr*)(buffer + ip_head->ip_hl + sizeof(struct ethhdr));
            if (is_src && udp->uh_sport == UDP){
                DPRINTF("UDP is suitable%u\n", udp->uh_sport);
                return 1;
            }
            else if( udp->uh_dport == UDP){
                DPRINTF("UDP is suitable%u\n", udp->uh_dport);
                return 1;
            }
            else{
                DPRINTF("UDP not suit %u->%u\n",udp->uh_sport, udp->uh_dport);
                
            }

        }
        else{
            //is not udp
            return 0;
        }


    }
    else if(ether->ether_type == 0x86DD){
        //TBD
        return 0;
    }
    return 0;
}

// обрабатывает пакет, если проходит по фильтрам, то добавляем к собираемой статистике
void data_process(char* buffer, int buflen, struct filter* filters, int filters_len){
    for (int i=0; i<filters_len; i++){
        int is_suitable = 1;

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
            is_suitable *= check_IPv4(buffer, buflen, filters[i].dst_IPv4, 0);
        }
        if(filters[i].flags.src_IPv4_flag){
            is_suitable *= check_IPv4(buffer, buflen, filters[i].src_IPv4, 1);
        }
        if(filters[i].flags.dst_IPv6_flag){
            is_suitable *= check_IPv6(buffer, buflen, filters[i].dst_IPv6, 0);
        }
        if(filters[i].flags.src_IPv6_flag){
            is_suitable *= check_IPv6(buffer, buflen, filters[i].src_IPv6, 1);
        }
        if(filters[i].flags.IP_protocol_flag){
            is_suitable *= check_IP_protocol(buffer, buflen, filters[i].IP_protocol);
        }
        if(filters[i].flags.dst_TCP_flag){
            is_suitable *= check_TCP(buffer, buflen, filters[i].dst_TCP, 0);
        }
        if(filters[i].flags.src_TCP_flag){
            is_suitable *= check_TCP(buffer, buflen, filters[i].src_TCP, 1);
        }
        if(filters[i].flags.dst_UDP_flag){
            is_suitable *= check_UDP(buffer, buflen, filters[i].dst_UDP, 0);
        }
        if(filters[i].flags.src_UDP_flag){
            is_suitable *= check_UDP(buffer, buflen, filters[i].src_UDP, 1);
        }

        if(is_suitable){
            filters[i].count_packets += 1;
            filters[i].size += buflen;
            DPRINTF("SUITABLE!!!!!!!!!!!!!!!! +1 packet on filter %d: %ld\n", i, filters[i].count_packets);
            printf("Ethernet Header \n");
            struct ether_header const* const ether = (struct ether_header const*)buffer;
            printf("dest Mac ");
            print_mac_addr(ether->ether_dhost);
            printf("sourse Mac ");
            print_mac_addr(ether->ether_shost);

            printf("Ether type %u\n", ether->ether_type);

            if (ether->ether_type == 8){
                ip_header(buffer, buflen);
            }
        }
        else{
            DPRINTF("NOT SUITABLE  %ld\n", filters[i].count_packets);
            
            struct ether_header const* const ether = (struct ether_header const*)buffer;
            if (ether->ether_type == 8){
                ip_header(buffer, buflen);
            }
        }
       
    }


    
    
}

char* get_statistics(struct filter* filters,  int* filters_len){
    return "success";
}


bool parse_mac(const char* str, struct ether_addr* mac) {
    return sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                 &mac->ether_addr_octet[0], &mac->ether_addr_octet[1],
                 &mac->ether_addr_octet[2], &mac->ether_addr_octet[3],
                 &mac->ether_addr_octet[4], &mac->ether_addr_octet[5]) == 6;
}

struct filter add_filter(char* buff, char** message){
    
    char* end = strchr(buff, '\r');
    if (end) {
        *end = 0;
    } else {
        end = strchr(buff, '\n');
        if (end)
            *end = 0;
    }
    struct filter new_filter = {0};

    char* token = strtok(buff + strlen("add filter"), " ");
    if (!token){
        *message = "Error: No filter parameters";
        return new_filter;
    } 
    

    
    while (token != NULL) {
        char* next_token = strtok(NULL, " ");
        if (!next_token) {
            *message = "Error: No filter ";
            return new_filter;
        }

        else if (strcmp(token, "dst_MAC") == 0) {
            if (!parse_mac(next_token, &new_filter.dst_MAC)) {
                *message = "Error: filter dst_MAC\n";
                return new_filter;
            }
            new_filter.flags.dst_MAC_flag = 1;
        }
        else if (strcmp(token, "src_MAC") == 0) {
            if (!parse_mac(next_token, &new_filter.src_MAC)) {
                *message = "Error:  filter src_MAC\n";
                return new_filter;
            }
            new_filter.flags.src_MAC_flag = 1;
        }
        else if (strcmp(token, "ether_type") == 0) {
            new_filter.ether_type = (uint16_t)strtoul(next_token, NULL, 0);
            new_filter.flags.ether_type_flag = 1;
        }
        else if (strcmp(token, "dst_IPv4") == 0) {
            int result = inet_pton(AF_INET, next_token, &new_filter.dst_IPv4);
            if (!result) {
                printf("error: Not in presentation format %s  %s\n ", next_token, inet_ntoa(new_filter.dst_IPv4));
                *message = "Error:filter dst_IPv4\n";
                return new_filter;
            }
            if (result<0)
               perror("inet_pton");
               new_filter.flags.dst_IPv4_flag = 1;
        }
        else if (strcmp(token, "src_IPv4") == 0) {
            if (inet_pton(AF_INET, next_token, &new_filter.src_IPv4) != 1) {
                *message = "Error:filter src_IPv4\n";
                return new_filter;
            }
            new_filter.flags.src_IPv4_flag = 1;
        }
        else if (strcmp(token, "dst_IPv6") == 0) {
            if (inet_pton(AF_INET6, next_token, &new_filter.dst_IPv6) != 1) {
                *message = "Error:  filter dst_IPv6\n";
                return new_filter;
            }
            new_filter.flags.dst_IPv6_flag = 1;
        }
        else if (strcmp(token, "src_IPv6") == 0) {
            if (inet_pton(AF_INET6, next_token, &new_filter.src_IPv6) != 1) {
                *message ="Error:  filter src_IPv6\n";
                return new_filter;
            }
            new_filter.flags.src_IPv6_flag = 1;
        }
        else if (strcmp(token, "IP_protocol") == 0) {
            new_filter.IP_protocol = (uint8_t)strtoul(next_token, NULL, 0);
            new_filter.flags.IP_protocol_flag = 1;
        }
        else if (strcmp(token, "src_TCP") == 0) {
            new_filter.src_TCP = (uint16_t)strtoul(next_token, NULL, 0);
            new_filter.flags.src_TCP_flag = 1;
        }
        else if (strcmp(token, "dst_TCP") == 0) {
            new_filter.dst_TCP = (uint16_t)strtoul(next_token, NULL, 0);
            new_filter.flags.dst_TCP_flag = 1;
        }
        else if (strcmp(token, "src_UDP") == 0) {
            new_filter.src_UDP = (uint16_t)strtoul(next_token, NULL, 0);
            new_filter.flags.src_UDP_flag = 1;
        }
        else if (strcmp(token, "dst_UDP") == 0) {
            new_filter.dst_UDP = (uint16_t)strtoul(next_token, NULL, 0);
            new_filter.flags.dst_UDP_flag = 1;
        }
        else {
            *message ="Error:  unknown key \n";
            return new_filter;
        }
        
        token = strtok(NULL, " ");
    }
    
    *message = "success\n";
    return new_filter;
}

char* delete_filter(char* buff, struct filter* filters,  int* filters_len){
    return "success\n";
}

void input_from_client(int connfd, struct filter* filters,  int* filters_len){
    char buff[MAX_MESSAGE] = {};   
    read(connfd, buff, sizeof(buff)); 
     
    printf("From client: %s\t", buff); 
    char* message;

    if (strncmp("add filter", buff,  10) == 0){
        filters[*filters_len] = add_filter(buff, &message);
        *filters_len +=1;
    }

    if (strncmp( "delete filter", buff, 13) == 0){
        message = delete_filter(buff, filters, filters_len);
        
    }

    if (strncmp("print", buff,  5) == 0){ 
        message  = get_statistics(filters, filters_len);
       
    }
    if (strncmp("exit", buff,  4) == 0){ 
        message  = "exiting";
        keepRunning = 0;
        
    }
    send(connfd, message, strlen(message) , MSG_NOSIGNAL); 
        
}



int main(int argc, char* argv[]){
    signal(SIGINT, handler);
    void* prev = signal(SIGPIPE, SIG_IGN);
    if (prev == SIG_ERR)
        return EXIT_FAILURE;
    int  sock_r, connfd, sock_listen, saddr_len, buflen;
    int filters_len = 0;
    struct sockaddr saddr;
    // int max_filters = 10; // как аргумент при запуске должен быть

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

    if (setsockopt(sock_listen, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
        perror("setsockopt(SO_REUSEADDR) failed");
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

    struct filter* filters = (struct filter *)malloc(sizeof(struct filter) * MAX_FILTERS); 

    
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
            input_from_client(connfd, filters, &filters_len);
        }
        if(fds[1].revents &POLLHUP||fds[1].revents &POLLERR){
            printf("closing connection\n");
            is_already_established=0;
            close(connfd);
        }
        



    }

    
    close(sock_r);
    close(sock_listen);
    close(connfd); 

    printf("DONE!!!!\n");
}