#include "printers.h"
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

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
 * @param buffer    buffer that starts with tcp head
 * @param bufflen   size of buffer
 * @param iphdrlen  size of ip header in bytes
 *
 * @sa print_payload
 */
static void
tcp_header(char const *buffer, size_t bufflen)
{
    struct tcphdr tcp_head;
    memcpy(&tcp_head, buffer, sizeof(struct tcphdr));
    printf("tcp Header \n");
    printf("Source tcp         :   %u\n", ntohs(tcp_head.th_sport));
    printf("Destination tcp    :   %u\n", ntohs(tcp_head.th_dport));
    char const *tcp_data = buffer + tcp_head.th_off*IHL_WORD_LEN;
    size_t message_len = bufflen - tcp_head.th_off*IHL_WORD_LEN;
    printf("tcp payload        :   %ld bytes\n",  message_len);
    print_payload(tcp_data, message_len);
    printf("\n###########################################################");
    printf("\n\n ");
}

/**
 * Print udp header of a packet.
 *
 * @param buffer     buffer that starts with tcp head
 * @param bufflen   size of buffer
 * @param iphdrlen  size of ip header in bytes
 *
 * @sa print_payload
 */
void
udp_header(char const *buffer, size_t bufflen)
{
    static size_t const udp_header_len = 8;
    struct udphdr udp_head;
    memcpy(&udp_head, buffer , sizeof(struct udphdr));
    printf("udp Header \n");
    printf("Source udp         :   %u\n", ntohs(udp_head.uh_sport));
    printf("Destination udp    :   %u\n", ntohs(udp_head.uh_dport));
    char const *udp_data = buffer + udp_header_len;
    size_t message_len = bufflen - udp_header_len;
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
print_ipv4(char const *buffer, size_t buf_flen)
{
    struct ip ip_head;
    memcpy(&ip_head, buffer, sizeof(struct ip));
    printf("ip Header\n");
    printf("Version           :    %u\n", ip_head.ip_v);
    printf("header length     :    %u\n", ip_head.ip_hl);
    printf("Type of service   :    %u\n", ip_head.ip_tos);
    printf("protocol          :    %u\n", ip_head.ip_p);
    printf("Source ip         :    %s\n", inet_ntoa(ip_head.ip_src));
    printf("Destination ip    :    %s\n",inet_ntoa(ip_head.ip_dst));

    switch(ip_head.ip_p) {

        case IPPROTO_TCP:
            tcp_header(buffer + ip_head.ip_hl*IHL_WORD_LEN, buf_flen - ip_head.ip_hl*IHL_WORD_LEN);
            break;

        case IPPROTO_UDP:
            udp_header(buffer + ip_head.ip_hl*IHL_WORD_LEN, buf_flen - ip_head.ip_hl*IHL_WORD_LEN);
            break;

        default:
            printf("\n\n");
    }
}

void
print_ipv6(char const *buffer, size_t bufflen)
{
    struct ip6_hdr  ip6_head;
    memcpy(&ip6_head, buffer, sizeof(struct ip6_hdr));

    /* Make strings of src and dst ipv6 adresses*/
    char ipv6_src_addr_string[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, &ip6_head.ip6_src, ipv6_src_addr_string, INET6_ADDRSTRLEN) == NULL) {
        perror("inet_ntop");
        return;
    }
    char ipv6_dst_addr_string[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, &ip6_head.ip6_dst, ipv6_dst_addr_string, INET6_ADDRSTRLEN) == NULL) {
        perror("inet_ntop");
        return;
    }

    printf("ip Version 6 Header\n");
    printf("protocol          :    %u\n", ip6_head.ip6_ctlun.ip6_un1.ip6_un1_nxt);
    printf("Source ip         :    %s\n", ipv6_src_addr_string);
    printf("Destination ip    :    %s\n", ipv6_dst_addr_string);

    size_t offset = sizeof(struct ip6_hdr);
    static const int IP6_HEADER_UNIT_SIZE = 8;


    uint8_t next_header = ip6_head.ip6_ctlun.ip6_un1.ip6_un1_nxt;
    while (offset < bufflen) {
        printf("ipv6 protocol: %u\n", next_header);
        switch (next_header) {
            case IPPROTO_HOPOPTS:    /* Hop-by-Hop options */
            case IPPROTO_ROUTING:    /* Routing header */
            case IPPROTO_FRAGMENT:   /* Fragmentation header */
            case IPPROTO_ESP:        /* Encapsulating Security Payload */
            case IPPROTO_AH:         /* Authentication Header */
            case IPPROTO_DSTOPTS:    /* Destination Options */
            {
                if (offset + IP6_HEADER_UNIT_SIZE > bufflen)
                    return;
                struct ip6_ext ext;
                memcpy(&ext, buffer + offset, sizeof(struct ip6_ext));
                next_header = ext.ip6e_nxt;
                offset += (ext.ip6e_len + 1) * IP6_HEADER_UNIT_SIZE;
                break;
            }
            case IPPROTO_TCP:
                if (offset + sizeof(struct tcphdr) <= bufflen) {
                    tcp_header(buffer + offset, bufflen - offset);
                }
                return;
            case IPPROTO_UDP:
                if (offset + sizeof(struct udphdr) <= bufflen) {
                    udp_header(buffer + offset, bufflen - offset);
                }
                return;
            default:
                return; /* unknown protocol */
        }
    }
}

void
print_vlan(char const *buffer, size_t bufflen){
    uint16_t vlan_tci;
    memcpy(&vlan_tci, buffer, sizeof(uint16_t));

    uint16_t vlan_id = ntohs(vlan_tci) & 0x0FFF;
    printf("VLAN ID: %d\n", vlan_id);

    uint16_t ether_type;
    memcpy(&ether_type, buffer+sizeof(uint16_t), sizeof(uint16_t));
    printf("Ether type        :    0x%04x\n", ntohs(ether_type));
    switch(ntohs(ether_type))
    {
        case ETHERTYPE_IP:
            print_ipv4(buffer+sizeof(uint16_t), bufflen-sizeof(uint16_t));
            break;

        case ETHERTYPE_IPV6:
            print_ipv6(buffer+sizeof(uint16_t), bufflen-sizeof(uint16_t));
            break;

        case ETHERTYPE_VLAN:
            print_vlan(buffer+sizeof(uint16_t), bufflen-sizeof(uint16_t));
            break;

        default:
            printf("\n###########################################################");
            printf("\n\n ");
            break;
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
print_packet(char const *buffer, size_t bufflen,  struct sockaddr_ll sniffaddr)
{
    char ifname[IF_NAMESIZE];
    if_indextoname(sniffaddr.sll_ifindex, ifname);
    printf("Interface: %s\n", ifname);

    printf("Ethernet Header \n");

    struct ether_header ether_head;
    memcpy(&ether_head, buffer, sizeof(ether_head));
    printf("Destination MAC   :    ");
    print_mac_addr(ether_head.ether_dhost);
    printf("Sourse      MAC   :    ");
    print_mac_addr(ether_head.ether_shost);

    switch(ntohs(ether_head.ether_type))
    {
        case ETHERTYPE_IP:
            printf("Ether type        :    0x%04x\n", ntohs(ether_head.ether_type));
            print_ipv4(buffer+sizeof(struct ether_header), bufflen-sizeof(struct ether_header));
            break;

        case ETHERTYPE_IPV6:
            print_ipv6(buffer+sizeof(struct ether_header), bufflen-sizeof(struct ether_header));
            break;

        case ETHERTYPE_VLAN:
            printf("TPID              :    0x%04x\n", ntohs(ether_head.ether_type));
            print_vlan(buffer+sizeof(struct ether_header), bufflen-sizeof(struct ether_header));
            break;


        default:
            break;
    }
}