/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2022 OKTET Labs Ltd. All rights reserved. */
/** @file
 * @brief Packet dissection and displaying.
 *
 * Implements layered packet parsing architecture for terminal output.
 */

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

/* Print MAC address */
void
ts_print_mac_addr(uint8_t const *addr)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
        addr[0], addr[1], addr[2],addr[3],addr[4],addr[5]);
}

/* Print data of a packet like hexdump. */
void
ts_print_payload(char const *data, size_t size)
{
    size_t line_start;

    if (size <= 0)
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

            line_start = i - (i % 16);
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

/* Print tcp header of a packet. */
void
ts_tcp_header(char const *buffer, size_t bufflen)
{
    struct tcphdr tcp_head;
    char const *tcp_data;
    size_t message_len;

    memcpy(&tcp_head, buffer, sizeof(struct tcphdr));
    printf("tcp Header \n");
    printf("Source tcp         :   %u\n", ntohs(tcp_head.th_sport));
    printf("Destination tcp    :   %u\n", ntohs(tcp_head.th_dport));
    tcp_data = buffer + tcp_head.th_off * IHL_WORD_LEN;
    message_len = bufflen - tcp_head.th_off * IHL_WORD_LEN;
    printf("tcp payload        :   %ld bytes\n",  message_len);
    ts_print_payload(tcp_data, message_len);
    printf("\n###########################################################");
    printf("\n\n ");
}

/* Print udp header of a packet. */
void
ts_udp_header(char const *buffer, size_t bufflen)
{
    static size_t const udp_header_len = 8;
    struct udphdr udp_head;
    char const *udp_data;
    size_t message_len;

    memcpy(&udp_head, buffer , sizeof(struct udphdr));
    printf("udp Header \n");
    printf("Source udp         :   %u\n", ntohs(udp_head.uh_sport));
    printf("Destination udp    :   %u\n", ntohs(udp_head.uh_dport));
    udp_data = buffer + udp_header_len;
    message_len = bufflen - udp_header_len;
    printf("udp payload        :   %ld bytes\n",  message_len);
    ts_print_payload(udp_data, message_len);
    printf("\n###########################################################");
    printf("\n\n ");
}


/* Print ip header of a packet. */
void
ts_print_ipv4(char const *buffer, size_t bufflen)
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

    /* Calculating the next header. */
    buffer +=  ip_head.ip_hl*IHL_WORD_LEN;
    bufflen -= ip_head.ip_hl*IHL_WORD_LEN;

    switch(ip_head.ip_p) {

        case IPPROTO_TCP:
            ts_tcp_header(buffer, bufflen );
            break;

        case IPPROTO_UDP:
            ts_udp_header(buffer, bufflen);
            break;

        default:
            printf("\n\n");
    }
}

/* Print ipv6 header of a packet. */
void
ts_print_ipv6(char const *buffer, size_t bufflen)
{
    static const int IP6_HEADER_UNIT_SIZE = 8;
    struct ip6_hdr  ip6_head;
    char const *buffer_end = buffer + bufflen;
    char ipv6_src_addr_string[INET6_ADDRSTRLEN];
    char ipv6_dst_addr_string[INET6_ADDRSTRLEN];
    uint8_t next_header;
    struct ip6_ext ext;

    memcpy(&ip6_head, buffer, sizeof(struct ip6_hdr));

    /* Make strings of src and dst ipv6 adresses*/
    if (inet_ntop(AF_INET6, &ip6_head.ip6_src, ipv6_src_addr_string, INET6_ADDRSTRLEN) == NULL) {
        perror("inet_ntop");
        return;
    }
    if (inet_ntop(AF_INET6, &ip6_head.ip6_dst, ipv6_dst_addr_string, INET6_ADDRSTRLEN) == NULL) {
        perror("inet_ntop");
        return;
    }

    printf("ip Version 6 Header\n");
    printf("protocol          :    %u\n", ip6_head.ip6_ctlun.ip6_un1.ip6_un1_nxt);
    printf("Source ip         :    %s\n", ipv6_src_addr_string);
    printf("Destination ip    :    %s\n", ipv6_dst_addr_string);

    /* Counting start the next head. */
    buffer += sizeof(struct ip6_hdr);

    next_header = ip6_head.ip6_ctlun.ip6_un1.ip6_un1_nxt;
    while (buffer < buffer_end) {
        switch (next_header) {
            case IPPROTO_HOPOPTS:    /* Hop-by-Hop options */
            case IPPROTO_ROUTING:    /* Routing header */
            case IPPROTO_FRAGMENT:   /* Fragmentation header */
            case IPPROTO_ESP:        /* Encapsulating Security Payload */
            case IPPROTO_AH:         /* Authentication Header */
            case IPPROTO_DSTOPTS:    /* Destination Options */
            {
                if (buffer + IP6_HEADER_UNIT_SIZE < buffer_end)
                    return;
                memcpy(&ext, buffer, sizeof(struct ip6_ext));
                next_header = ext.ip6e_nxt;
                buffer += (ext.ip6e_len + 1) * IP6_HEADER_UNIT_SIZE;
                bufflen -= (ext.ip6e_len + 1) * IP6_HEADER_UNIT_SIZE;
                break;
            }
            case IPPROTO_TCP:
                ts_tcp_header(buffer, bufflen);
                return;
            case IPPROTO_UDP:
                ts_udp_header(buffer, bufflen);
                return;
            default:
                return; /* unknown protocol */
        }
    }
}

/* Print vlan header of a packet. */
void
ts_print_vlan(char const *buffer, size_t bufflen){
    uint16_t vlan_tci;
    uint16_t vlan_id;
    uint16_t ether_type;

    memcpy(&vlan_tci, buffer, sizeof(uint16_t));

    vlan_id = ntohs(vlan_tci) & MASK_VLAN_ID;
    printf("VLAN ID: %d\n", vlan_id);

    /* Calculating the next header. */
    buffer += sizeof(vlan_tci);
    bufflen -= sizeof(vlan_tci);

    memcpy(&ether_type, buffer, sizeof(uint16_t));
    printf("Ether type        :    0x%04x\n", ntohs(ether_type));

    /* Calculating the next header. */
    buffer += sizeof(ether_type);
    bufflen -= sizeof(ether_type);

    switch(ntohs(ether_type))
    {
        case ETHERTYPE_IP:
            ts_print_ipv4(buffer, bufflen);
            break;

        case ETHERTYPE_IPV6:
            ts_print_ipv6(buffer, bufflen);
            break;

        case ETHERTYPE_VLAN:
            ts_print_vlan(buffer, bufflen);
            break;

        default:
            printf("\n###########################################################");
            printf("\n\n ");
            break;
    }
}

/* Print interface and ethernet header of a packet.*/
void
ts_print_packet(char const *buffer, size_t bufflen,  struct sockaddr_ll sniffaddr)
{
    char ifname[IF_NAMESIZE];
    struct ether_header ether_head;

    errno = 0;
    if (if_indextoname(sniffaddr.sll_ifindex, ifname) == NULL)
    {
        printf("Interface: invalid \n");
        return;
    }

    printf("Interface: %s\n", ifname);
    printf("Ethernet Header \n");

    memcpy(&ether_head, buffer, sizeof(ether_head));
    printf("Destination MAC   :    ");
    ts_print_mac_addr(ether_head.ether_dhost);
    printf("Sourse      MAC   :    ");
    ts_print_mac_addr(ether_head.ether_shost);

    /* Calculating the next header. */
    buffer += sizeof(ether_head);
    bufflen -= sizeof(ether_head);

    switch(ntohs(ether_head.ether_type))
    {
        case ETHERTYPE_IP:
            printf("Ether type        :    0x%04x\n", ntohs(ether_head.ether_type));
            ts_print_ipv4(buffer, bufflen);
            break;

        case ETHERTYPE_IPV6:
            ts_print_ipv6(buffer, bufflen);
            break;

        case ETHERTYPE_VLAN:
            printf("TPID              :    0x%04x\n", ntohs(ether_head.ether_type));
            ts_print_vlan(buffer, bufflen);
            break;
        default:
            break;
    }
}