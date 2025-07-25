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


#define MAX_PORTS 65536
static volatile int keepRunning = 1;

void data_process(char* buffer, int buflen){
    printf("Ethernet Header \n");
    printf("dest MAC %hhX:%hhX:%hhX:%hhX:%hhX:%hhX\n", buffer[0], buffer[1],buffer[2],buffer[3],buffer[4],buffer[5]);
    printf("src MAC %hhX:%hhX:%hhX:%hhX:%hhX:%hhX \n", buffer[6], buffer[7],buffer[8],buffer[9],buffer[10],buffer[11]);
    printf("Ether type %hhX %hhX\n", buffer[12], buffer[13]);
    
    
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
