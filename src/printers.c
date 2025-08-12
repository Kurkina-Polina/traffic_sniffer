#include "printers.h"
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
/**
 * Print MAC address.
 *
 * @param addr    MAC address in uint8_t
 */
static void
print_mac_addr(uint8_t const *addr)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
        addr[0], addr[1], addr[2],addr[3],addr[4],addr[5]);
}

/**
 * Print data of a packet like hexdump.
 *
 * @param data    pointer of start data
 * @param size    size of data
 */
static void
print_payload(char const *data, size_t size)
{
    if (size <=0 )
    {
        printf("No payload");
        return;
    }
    for (size_t i = 0; i < size; i++)
    {
        if (i % 16 == 0)
            printf("%04zx:  ", i);

        printf("%02x ", (unsigned char)data[i]);

        if (i % 16 == 15 || i == size - 1)
        {
            if (i % 16 != 15)
                for (size_t j = 0; j < 15 - (i % 16); j++)
                    printf("   ");

            printf("  |");

            size_t line_start = i - (i % 16);
            for (size_t j = line_start; j <= i; j++)
            {
                if (data[j] >= 32 && data[j] <= 126)
                    printf("%c", data[j]);
                else
                    printf(".");
            }

            printf("|\n");
        }
    }
}

/**
 * Print tcp header of a packet.
 *
 * @param buffer    full buffer, received from client
 * @param bufflen   size of buffer
 * @param iphdrlen  size of ip header in bytes
 *
 * @sa print_payload
 */
static void
tcp_header(char const *buffer, size_t bufflen, size_t iphdrlen)
{
    struct tcphdr const *tcp = (struct tcphdr const*)(buffer +
        iphdrlen + sizeof(struct ethhdr));
    printf("tcp Header \n");
    printf("Source tcp         :   %u\n", ntohs(tcp->th_sport));
    printf("Destination tcp    :   %u\n", ntohs(tcp->th_dport));
    char const *tcp_data = buffer + sizeof(struct ethhdr) + iphdrlen + tcp->th_off*IHL_WORD_LEN;
    size_t message_len = bufflen - (sizeof(struct ethhdr) + iphdrlen + tcp->th_off*IHL_WORD_LEN);
    printf("tcp payload        :   %ld bytes\n",  message_len);
    print_payload(tcp_data, message_len);
    printf("\n###########################################################");
    printf("\n\n ");
}

/**
 * Print udp header of a packet.
 *
 * @param buffer    full buffer, received from client
 * @param bufflen   size of buffer
 * @param iphdrlen  size of ip header in bytes
 *
 * @sa print_payload
 */
void
udp_header(char const *buffer, size_t bufflen, size_t iphdrlen)
{
    static size_t const udp_header_len = 8;
    struct udphdr const *udp = (struct udphdr const*)(buffer
        + iphdrlen + sizeof(struct ethhdr));
    printf("udp Header \n");
    printf("Source udp         :   %u\n", ntohs(udp->uh_sport));
    printf("Destination udp    :   %u\n", ntohs(udp->uh_dport));
    char const *udp_data = buffer + sizeof(struct ethhdr) + iphdrlen + udp_header_len;
    size_t message_len = bufflen - (sizeof(struct ethhdr) + iphdrlen + udp_header_len);
    printf("udp payload        :   %ld bytes\n",  message_len);
    print_payload(udp_data, message_len);
    printf("\n###########################################################");
    printf("\n\n ");
}


/**
 * Print ip header of a packet.
 *
 * @param buffer    full buffer, received from client
 * @param buf_flen   size of buffer
 *
 * @sa tcp_header udp_header
 */
void
ip_header(char const *buffer, size_t buf_flen)
{
    struct ip const *const ip_head = (struct ip const*)(buffer
        + sizeof(struct ether_header));
    printf("ip Header\n");
    printf("Version           :    %u\n", ip_head->ip_v);
    printf("header length     :    %u\n", ip_head->ip_hl);
    printf("Type of service   :    %u\n", ip_head->ip_tos);
    printf("protocol          :    %u\n", ip_head->ip_p);
    printf("Source ip         :    %s\n", inet_ntoa(ip_head->ip_src));
    printf("Destination ip    :    %s\n",inet_ntoa(ip_head->ip_dst));

    switch(ip_head->ip_p) {

        case IPPROTO_TCP:
            tcp_header(buffer, buf_flen, ip_head->ip_hl*IHL_WORD_LEN);
            break;

        case IPPROTO_UDP:
            udp_header(buffer, buf_flen, ip_head->ip_hl*IHL_WORD_LEN);
            break;

        default:
            printf("\n\n");
    }
}

/**
 * Print all headers of packet and data.
 *
 * @param buffer    full buffer, received from client
 * @param bufflen   size of buffer
 *
 * @sa ip_header
 */
void
print_packet(char const *buffer, size_t bufflen)
{
    printf("Ethernet Header \n");
    struct ether_header const *const ether = (struct ether_header const*)buffer;
    printf("Destination MAC   :    ");
    print_mac_addr(ether->ether_dhost);
    printf("Sourse      MAC   :    ");
    print_mac_addr(ether->ether_shost);

    printf("Ether type        :    %u\n", ntohs(ether->ether_type));

    switch(ntohs(ether->ether_type))
    {
        case ETHERTYPE_IP:
            ip_header(buffer, bufflen);
            break;

        default:
            break;
    }
}