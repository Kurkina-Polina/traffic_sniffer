#include<stdio.h>
#include<malloc.h>
#include<string.h>
#include<signal.h>
#include<stdbool.h>

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


void print_mac_addr(uint8_t const* const addr) {
    printf("%d:%d:%d:%d:%d:%d \n", addr[0], addr[1], addr[2],addr[3],addr[4],addr[5]);
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

#define MAX_PORTS 65536
static volatile int keepRunning = 1;

void data_process(char* buffer, int buflen){
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


void handler(){
    keepRunning = 0;
}

int main(int argc, char* argv[]){
    signal(SIGINT, handler);
    int  sock_r, saddr_len,buflen;
    struct sockaddr saddr;

    unsigned char* buffer = (unsigned char *)malloc(MAX_PORTS); 
    memset(buffer,0,MAX_PORTS);

    printf("starting .... \n");

    // Open raw socket on on Ethernet layer.
    sock_r = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL)); 
    if(sock_r<0)
    {
        perror("error in socket\n");
        return -1;
    }

    
    while(keepRunning)
    {
        saddr_len = sizeof saddr;
        buflen = read(sock_r,buffer, MAX_PORTS);

        if(buflen<0)
        {
            printf("error in reading recvfrom function\n");
            return -1;
        }
        // fflush(log_txt);
        data_process(buffer,buflen);
        // for (size_t i = 0; i < buflen; i++) 
        //     putchar(buffer[i]);
        // putchar('\n');
    }
    close(sock_r);
    printf("DONE!!!!\n");
}