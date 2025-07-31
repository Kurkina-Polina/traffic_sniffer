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
    int dst_mac_flag;
    int src_mac_flag;
    int ether_type_flag;
    int dst_ipv4_flag;
    int src_ipv4_flag;
    int dst_ipv6_flag;
    int src_ipv6_flag;
    int ip_protocol_flag;
    int dst_tcp_flag;
    int src_tcp_flag;
    int dst_udp_flag;
    int src_udp_flag;
};

struct filter{
    uint16_t vlan_id;
    struct ether_addr dst_mac;
    struct ether_addr src_mac;
    uint16_t ether_type;
    struct in_addr dst_ipv4;
    struct in_addr src_ipv4;
    struct in6_addr dst_ipv6;
    struct in6_addr src_ipv6;
    uint8_t ip_protocol;
    uint16_t dst_tcp;
    uint16_t src_tcp;
    uint16_t dst_udp;
    uint16_t src_udp;

    size_t count_packets;
    size_t size;
    struct filter_flag flags;
   
};

void print_help(char** message){
    *message = "Usage: "
    "add <key> <value>  <key> <value> - add filter\n"
    "print - print statics on filters\n"
    "exit - to close connection"
    "del <number of filter> - delete filter by number - not supported yet\n"
    "\n"
    "possible keys:\n"
    "src_mac\n" 
    "dst_mac\n"
    "ether_type\n "
    "ip_protocol\n"
    "dst_ipv4\n"
    "src_ipv4\n"
    "dst_ipv6 not supported yet\n"
    "src_ipv6 not supported yet\n"
    "src_tcp\n"
    "dst_tcp\n"
    "src_udp\n"
    "dst_udp\n"
    "\n"
    "On one filter you can use only one same keys: you can't use key dst_udp twise. Only last will work.\n"
    "Maximum size of filters is 10\n";
}

void print_mac_addr(uint8_t const* const addr) {
    printf("%d:%d:%d:%d:%d:%d \n", addr[0], addr[1], addr[2],addr[3],addr[4],addr[5]);
}

void handler(){
    keepRunning = 0;
}

void print_payload(char const* data, size_t size){
    if (size <=0 ){
        printf("No payload");
        return;
    }
    for (size_t i = 0; i < size; i++) {
        // Вывод hex-значений
        if (i % 16 == 0) {
            // Вывод адреса в начале строки
            printf("%04zx:  ", i);
        }

        printf("%02x ", (unsigned char)data[i]);

        // ASCII-представление в конце строки
        if (i % 16 == 15 || i == size - 1) {
            // Выравнивание для неполных строк
            if (i % 16 != 15) {
                for (size_t j = 0; j < 15 - (i % 16); j++) {
                    printf("   ");
                }
            }

            printf("  |");

            // Вывод ASCII-символов
            size_t line_start = i - (i % 16);
            for (size_t j = line_start; j <= i; j++) {
                if (data[j] >= 32 && data[j] <= 126) {
                    printf("%c", data[j]);
                } else {
                    printf(".");
                }
            }

            printf("|\n");
        }
    }
}

void  tcp_header(char* buffer, int bufflen, int iphdrlen){
    struct tcphdr *tcp = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
    printf("tcp Header \n");
    printf("Source tcp         : %u\n", ntohs(tcp->th_sport));
    printf("Destination tcp    : %u\n", ntohs(tcp->th_dport));
    char* tcp_data = buffer + sizeof(struct ethhdr) + iphdrlen + tcp->th_off*4;
    size_t message_len = bufflen - (sizeof(struct ethhdr) + iphdrlen + tcp->th_off*4);
    printf("tcp payload (%ld bytes):\n",  message_len);
    print_payload(tcp_data, message_len);
    printf("\n\n ");

}

void udp_header(char* buffer, int bufflen, int iphdrlen){
    struct udphdr *udp = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
    printf("udp Header \n");
    printf("Source udp         : %u\n", ntohs(udp->uh_sport));
    printf("Destination udp    : %u\n", ntohs(udp->uh_dport));
    char* udp_data = buffer + sizeof(struct ethhdr) + iphdrlen + 8;
    size_t message_len = bufflen - (sizeof(struct ethhdr) + iphdrlen + 8);
    printf("udp payload (%ld bytes):\n",  message_len);
    print_payload(udp_data, message_len);
    printf("\n###########################################################");
    printf("\n\n ");
}

void ip_header(char* buffer, int bufflen){
    struct ip const* const ip_head = (struct ip const*)(buffer + sizeof(struct ether_header));
    printf("ip Header \n");
    printf("Version %u\n", ip_head->ip_v);
    printf("header length %u\n", ip_head->ip_hl);
    printf("Type of service. %u\n", ip_head->ip_tos);
    printf("protocol %u\n", ip_head->ip_p);
    printf("Source ip         : %s\n", inet_ntoa(ip_head->ip_src));
    printf("Destination ip    : %s\n",inet_ntoa(ip_head->ip_dst));
    

    if (ip_head->ip_p == 6){
        tcp_header(buffer, bufflen, ip_head->ip_hl*4);
    }
    else if(ip_head->ip_p == 17){
        udp_header(buffer, bufflen, ip_head->ip_hl*4);
    }
    else{
        printf("\n\n ");
    }
}

void print_packet(char* buffer, int bufflen){
    printf("Ethernet Header \n");
    struct ether_header const* const ether = (struct ether_header const*)buffer;
    printf("dest Mac ");
    print_mac_addr(ether->ether_dhost);
    printf("sourse Mac ");
    print_mac_addr(ether->ether_shost);

    printf("Ether type %u\n", ntohs(ether->ether_type));

    if (ntohs(ether->ether_type) == 0x0800){
        ip_header(buffer, bufflen);
    }
}

int check_vlan(char* buffer, int bufflen, uint16_t vlan_id){
    return 1;
}
int check_mac(char* buffer, int bufflen, struct ether_addr mac){
    struct ether_header const* const ether = (struct ether_header const*)buffer;
    uint8_t const* const addr = ether->ether_shost;
    for (int i =0; i<6; i++){
        if (mac.ether_addr_octet[i]!=addr[i]){
            
            return 0;
        }
    }

    return 1;
}
int check_ether_type(char* buffer, int bufflen, uint16_t ether_type){
    struct ether_header const* const ether = (struct ether_header const*)buffer;
    uint16_t ether_data = ether->ether_type;
    if(ether_data != ether_type){
        DPRINTF("it is not  %u != %u\n", ntohs(ether_data), ntohs(ether_type));
        return 0;
    }
    return 1;
}
int check_ipv4(char* buffer, int bufflen,  struct in_addr ipv, int is_scr){
    struct ether_header const* const ether = (struct ether_header const*)buffer;
    struct ip const* const ip_head = (struct ip const*)(buffer + sizeof(struct ether_header));
    if (ether->ether_type == 8){
        struct ip const* const ip_head = (struct ip const*)(buffer + sizeof(struct ether_header));
        if(is_scr){
            if(ip_head->ip_src.s_addr == ipv.s_addr){
                DPRINTF("it is %s=%s\n", inet_ntoa(ip_head->ip_src),  inet_ntoa(ipv));
                return 1;
            }
        }
        else{
            if(ip_head->ip_src.s_addr == ipv.s_addr){
                DPRINTF("it is %s=%s\n", inet_ntoa(ip_head->ip_src),  inet_ntoa(ipv));
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
int check_ipv6(char* buffer, int bufflen, struct in6_addr ipv6, int is_scr){
#if 0
    struct ether_header const* const ether = (struct ether_header const*)buffer;
    if (ether->ether_type == 0x86DD){
        struct in6_pktinfo const* const ip6_head = (struct in6_pktinfo const*)(buffer + sizeof(struct ether_header));
        if(is_scr){
            if(ip6_head->sin6_addr.s6_addr == ipv6.s6_addr){
                DPRINTF("it is %s=%s\n", inet_ntoa(ip_head->ip_src),  inet_ntoa(ipv6));
                return 1;
            }
        }
        else{
            if(ip6_head->sin6_addr.s6_addr == ipv6.s6_addr){
                DPRINTF("it is %s=%s\n", inet_ntoa(ip_head->ip_src),  inet_ntoa(ipv6));
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

int check_ip_protocol(char* buffer, int bufflen, uint8_t ip_protocol){
    struct ether_header const* const ether = (struct ether_header const*)buffer;
    if (ether->ether_type == 8){
        struct ip const* const ip_head = (struct ip const*)(buffer + sizeof(struct ether_header));
        if( ip_head->ip_p == ip_protocol){
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
int check_tcp(char* buffer, int bufflen, uint16_t tcp_port, int is_src){
    struct ether_header const* const ether = (struct ether_header const*)buffer;
    if (ether->ether_type == 8){
        struct ip const* const ip_head = (struct ip const*)(buffer + sizeof(struct ether_header));
        if (ip_head->ip_p == 6){
            struct tcphdr *tcp = (struct tcphdr*)(buffer + ip_head->ip_hl*4 + sizeof(struct ethhdr));
            if (is_src && tcp->th_sport == tcp_port){
                DPRINTF("tcp is suitable%u\n", ntohs(tcp->th_sport));
                return 1;
            }
            else if( tcp->th_dport == tcp_port){
                DPRINTF("tcp is suitable%u\n",ntohs(tcp->th_dport));
                return 1;
            }
            else{
                DPRINTF("tcp not suit %u -> %u \n", ntohs(tcp->th_sport), ntohs(tcp->th_dport));
                
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
int check_udp(char* buffer, int bufflen, unsigned short int udp_port, int is_src){
    struct ether_header const* const ether = (struct ether_header const*)buffer;
    if (ether->ether_type == 8){
        struct ip const* const ip_head = (struct ip const*)(buffer + sizeof(struct ether_header));
        if (ip_head->ip_p == 17){

            struct udphdr *udp = (struct udphdr*)(buffer + ip_head->ip_hl*4 + sizeof(struct ethhdr));
            if (is_src && udp->uh_sport == udp_port){
                DPRINTF("udp is suitable%u\n", ntohs(udp->uh_sport));
                return 1;
            }
            else if( udp->uh_dport == udp_port){
                DPRINTF("udp is suitable%u\n", ntohs(udp->uh_dport));
                return 1;
            }
            else{
                DPRINTF("udp not suit %u->%u\n",ntohs(udp->uh_sport), ntohs(udp->uh_dport));
                
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
void data_process(char* buffer, int bufflen, struct filter* filters, int filters_len){
    for (int i=0; i<filters_len; i++){
        int is_suitable = 1;

        if(filters[i].flags.dst_mac_flag){
            is_suitable *= check_mac(buffer, bufflen, filters[i].dst_mac);
        }
        
        if(filters[i].flags.src_mac_flag){
            is_suitable *= check_mac(buffer, bufflen, filters[i].src_mac);
        }
        if(filters[i].flags.ether_type_flag){
            is_suitable *=  check_ether_type(buffer, bufflen, filters[i].ether_type);
        }
        if(filters[i].flags.dst_ipv4_flag){
            is_suitable *= check_ipv4(buffer, bufflen, filters[i].dst_ipv4, 0);
        }
        if(filters[i].flags.src_ipv4_flag){
            is_suitable *= check_ipv4(buffer, bufflen, filters[i].src_ipv4, 1);
        }
        if(filters[i].flags.dst_ipv6_flag){
            is_suitable *= check_ipv6(buffer, bufflen, filters[i].dst_ipv6, 0);
        }
        if(filters[i].flags.src_ipv6_flag){
            is_suitable *= check_ipv6(buffer, bufflen, filters[i].src_ipv6, 1);
        }
        if(filters[i].flags.ip_protocol_flag){
            is_suitable *= check_ip_protocol(buffer, bufflen, filters[i].ip_protocol);
        }
        if(filters[i].flags.dst_tcp_flag){
            is_suitable *= check_tcp(buffer, bufflen, filters[i].dst_tcp, 0);
        }
        if(filters[i].flags.src_tcp_flag){
            is_suitable *= check_tcp(buffer, bufflen, filters[i].src_tcp, 1);
        }
        if(filters[i].flags.dst_udp_flag){
            is_suitable *= check_udp(buffer, bufflen, filters[i].dst_udp, 0);
        }
        if(filters[i].flags.src_udp_flag){
            is_suitable *= check_udp(buffer, bufflen, filters[i].src_udp, 1);
        }

        if(is_suitable){
            filters[i].count_packets += 1;
            filters[i].size += bufflen;
            DPRINTF("SUITABLE!!!!!!!!!!!!!!!! +1 packet on filter %d: %ld\n", i, filters[i].count_packets);
            print_packet(buffer, bufflen);
        }

        else{
            DPRINTF("NOT SUITABLE  %ld\n", filters[i].count_packets);
            print_packet(buffer, bufflen);
        }
       
    }


    
    
}

void get_statistics(struct filter* filters, int filters_len, char* message) {
    if(filters_len<=0){

    }
    
    message[0] = '\0';  
    if(filters_len<=0){
        char buffer[256];
        snprintf(buffer, sizeof(buffer), "No filters yet\n");
        strcat(message, buffer);  
    }
    
    for (int i = 0; i < filters_len; i++) {
        char buffer[MAX_MESSAGE];
        snprintf(buffer, sizeof(buffer), 
                "Filter number %d: packets=%ld, total_size=%ld bytes\n",
                i + 1, 
                filters[i].count_packets, 
                filters[i].size);
        
        
        strcat(message, buffer);  
    }
    
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

        else if (strcmp(token, "dst_mac") == 0) {
            if (!parse_mac(next_token, &new_filter.dst_mac)) {
                *message = "Error: filter dst_mac\n";
                return new_filter;
            }
            new_filter.flags.dst_mac_flag = 1;
        }
        else if (strcmp(token, "src_mac") == 0) {
            if (!parse_mac(next_token, &new_filter.src_mac)) {
                *message = "Error:  filter src_mac\n";
                return new_filter;
            }
            new_filter.flags.src_mac_flag = 1;
        }
        else if (strcmp(token, "ether_type") == 0) {
            new_filter.ether_type = htons((uint16_t)strtoul(next_token, NULL, 0));
            new_filter.flags.ether_type_flag = 1;
        }
        else if (strcmp(token, "dst_ipv4") == 0) {
            int result = inet_pton(AF_INET, next_token, &new_filter.dst_ipv4);
            if (!result) {
                printf("error: Not in presentation format %s  %s\n ", next_token, inet_ntoa(new_filter.dst_ipv4));
                *message = "Error:filter dst_ipv4\n";
                return new_filter;
            }
            if (result<0)
               perror("inet_pton");
               new_filter.flags.dst_ipv4_flag = 1;
        }
        else if (strcmp(token, "src_ipv4") == 0) {
            if (inet_pton(AF_INET, next_token, &new_filter.src_ipv4) != 1) {
                *message = "Error:filter src_ipv4\n";
                return new_filter;
            }
            new_filter.flags.src_ipv4_flag = 1;
        }
        else if (strcmp(token, "dst_ipv6") == 0) {
            if (inet_pton(AF_INET6, next_token, &new_filter.dst_ipv6) != 1) {
                *message = "Error:  filter dst_ipv6\n";
                return new_filter;
            }
            new_filter.flags.dst_ipv6_flag = 1;
        }
        else if (strcmp(token, "src_ipv6") == 0) {
            if (inet_pton(AF_INET6, next_token, &new_filter.src_ipv6) != 1) {
                *message ="Error:  filter src_ipv6\n";
                return new_filter;
            }
            new_filter.flags.src_ipv6_flag = 1;
        }
        else if (strcmp(token, "ip_protocol") == 0) {
            new_filter.ip_protocol = (uint8_t)strtoul(next_token, NULL, 0);
            new_filter.flags.ip_protocol_flag = 1;
        }
        else if (strcmp(token, "src_tcp") == 0) {
            new_filter.src_tcp = htons((uint16_t)strtoul(next_token, NULL, 0));
            new_filter.flags.src_tcp_flag = 1;
        }
        else if (strcmp(token, "dst_tcp") == 0) {
            new_filter.dst_tcp = htons((uint16_t)strtoul(next_token, NULL, 0));
            new_filter.flags.dst_tcp_flag = 1;
        }
        else if (strcmp(token, "src_udp") == 0) {
            new_filter.src_udp = htons((uint16_t)strtoul(next_token, NULL, 0));
            new_filter.flags.src_udp_flag = 1;
        }
        else if (strcmp(token, "dst_udp") == 0) {
            new_filter.dst_udp = htons((uint16_t)strtoul(next_token, NULL, 0));
            new_filter.flags.dst_udp_flag = 1;
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

    if (strncmp("add", buff, 3) == 0){
        filters[*filters_len] = add_filter(buff, &message);
        *filters_len +=1;
    }

    else if (strncmp( "del", buff, 3) == 0){
        message = delete_filter(buff, filters, filters_len);
        
    }

    else if (strncmp("print", buff,  5) == 0){ 
        message  = malloc (sizeof("Filter number %d: packets=%d, total_size=%d bytes\n")* *filters_len);
        get_statistics(filters, *filters_len, message);
       
    }
    else if (strncmp("exit", buff,  4) == 0){ 
        message  = "exiting\n";
        keepRunning = 0;
        
    }
    else{
        print_help(&message);
    }

    send(connfd, message, strlen(message) , MSG_NOSIGNAL); 
        
}



int main(int argc, char* argv[]){
    signal(SIGINT, handler);
    void* prev = signal(SIGPIPE, SIG_IGN);
    if (prev == SIG_ERR)
        return EXIT_FAILURE;
    int  sock_r, connfd, sock_listen, saddr_len, bufflen;
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
    // assign ip, PORT 
    int port = 8080;
    struct sockaddr_in servaddr, clientaddr; 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    servaddr.sin_port = htons(port); 
    
  
    // Binding newly created socket to given ip and verification 
    if ((bind(sock_listen, (struct sockaddr*)&servaddr, sizeof(servaddr))) != 0) { 
        perror("socket bind failed...\n"); 
        exit(0); 
    } 
    if ((listen(sock_listen, 5)) != 0) { 
        perror("Listen failed...\n"); 
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
            bufflen = read(sock_r,buffer, MAX_PORTS);

            if(bufflen<0)
            {
                perror("error in reading recvfrom function\n");
                return -1;
            }
            data_process(buffer, bufflen, filters,  filters_len);
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
