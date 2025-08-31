/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2022 OKTET Labs Ltd. All rights reserved. */
/** @file
 * @brief Dissecters headers.
 *
 * Input: pointer to start of header, size of all remaining headers and payload,
 * pointer to the current packet data, that is filling.
 */

#include "parsers_pkt.h"
#include <string.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>

/* Dissect tcp header and fill packet_data with dst_tcp and src_tcp. */
void
ts_parser_pkt_tcp(char const *buffer, size_t bufflen, struct filter *packet_data)
{
    struct tcphdr tcp_head;

    if (bufflen < sizeof(tcp_head))
        return;

    memcpy(&tcp_head, buffer, sizeof(tcp_head));
    packet_data->dst_tcp = tcp_head.th_dport;
    packet_data->src_tcp = tcp_head.th_sport;
}

/* Dissect udp header and fill packet_data with dst_udp and src_udp. */
void
ts_parser_pkt_udp(char const *buffer, size_t bufflen, struct filter *packet_data)
{
    struct udphdr udp_head;

    if (bufflen < sizeof(udp_head))
        return;

    memcpy(&udp_head, buffer, sizeof(udp_head));
    packet_data->src_udp = udp_head.uh_sport;
    packet_data->dst_udp = udp_head.uh_dport;
}

/* Dissect ipv4 header and fill packet_data with dst_ipv4, src_ipv4, ip_protocol. */
void
ts_parser_pkt_ipv4(char const *buffer, size_t bufflen, struct filter *packet_data)
{
    struct ip ip_head;

    if (bufflen < sizeof(ip_head))
        return;

    memcpy(&ip_head, buffer, sizeof(ip_head));
    packet_data->src_ipv4 = ip_head.ip_src;
    packet_data->dst_ipv4 = ip_head.ip_dst;
    packet_data->ip_protocol = ip_head.ip_p;

    /* Move pointer to the next header. */
    buffer += ip_head.ip_hl * IHL_WORD_LEN;
    bufflen -= ip_head.ip_hl * IHL_WORD_LEN;

    switch(ip_head.ip_p)
    {
        case IPPROTO_TCP:
            ts_parser_pkt_tcp(buffer, bufflen, packet_data);
            break;

        case IPPROTO_UDP:
            ts_parser_pkt_udp(buffer, bufflen, packet_data);
            break;

        default:
            break;
    }
}

/* Dissect ipv6 header and fill dst_ipv6, src_ipv6, ip_protocol. */
void
ts_parser_pkt_ipv6(char const *buffer, size_t bufflen, struct filter *packet_data)
{
    struct ip6_hdr  ip6_head;
    static const int IP6_HEADER_UNIT_SIZE = 8;
    char const *buffer_end = buffer + bufflen;
    uint8_t next_header; /* next header number */
    struct ip6_ext ext; /* struct of extension headers */

    if (bufflen < sizeof(ip6_head))
        return;

    memcpy(&ip6_head, buffer, sizeof(struct ip6_hdr));
    packet_data->src_ipv6 = ip6_head.ip6_src;
    packet_data->dst_ipv6 = ip6_head.ip6_dst;
    packet_data->ip_protocol = ip6_head.ip6_ctlun.ip6_un1.ip6_un1_nxt;

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
                ts_parser_pkt_tcp(buffer, bufflen, packet_data);
                return;

            case IPPROTO_UDP:
                ts_parser_pkt_udp(buffer, bufflen, packet_data);
                return;

            default:
                return; /* unknown protocol */
        }
    }
}

/* Dissect vlan header and fill packet_data with vlan_id. */
void
ts_parser_pkt_vlan(char const *buffer, size_t bufflen, struct filter *packet_data)
{
    uint16_t vlan_tci;
    uint16_t vlan_id;
    uint16_t ether_type;

    if (bufflen < sizeof(vlan_tci))
        return;
    memcpy(&vlan_tci, buffer, sizeof(uint16_t));
    buffer += sizeof(vlan_tci);

    vlan_id = ntohs(vlan_tci) & MASK_VLAN_ID;
    packet_data->vlan_id = vlan_id;

    memcpy(&ether_type, buffer, sizeof(ether_type));
    buffer += sizeof(ether_type); /* counting start the next head */
    bufflen -= (sizeof(ether_type) + sizeof(vlan_tci));
    packet_data->ether_type = ether_type;
    switch(ntohs(ether_type))
    {
        case ETHERTYPE_IP:
            ts_parser_pkt_ipv4(buffer, bufflen, packet_data);
            break;

        case ETHERTYPE_IPV6:
            ts_parser_pkt_ipv6(buffer, bufflen, packet_data);
            break;

        case ETHERTYPE_VLAN_8021AD:
        case ETHERTYPE_VLAN:
            ts_parser_pkt_vlan(buffer, bufflen, packet_data);
            break;

        default:
            break;
    }
}

/* Dissect ether header and fill packet_data with dst_mac, src_mac,
 * interface, ether_type. */
void
ts_parser_pkt_ether(char const *buffer, size_t bufflen, struct filter *packet_data, struct sockaddr_ll sniffaddr)
{
    struct ether_header ether_head;

    packet_data->interface = sniffaddr.sll_ifindex;

    if (bufflen < sizeof(ether_head))
        return;
    memcpy(&ether_head, buffer, sizeof(ether_head));
    memcpy(&(packet_data->dst_mac), &(ether_head.ether_dhost), sizeof(struct ether_addr));
    memcpy(&(packet_data->src_mac), &(ether_head.ether_shost), sizeof(struct ether_addr));
    packet_data->ether_type = ether_head.ether_type;

    buffer += sizeof(ether_head);  /* counting start the next head */
    bufflen -=  sizeof(ether_head);

    switch (ntohs(ether_head.ether_type))
    {
        case ETHERTYPE_IP:
            ts_parser_pkt_ipv4(buffer, bufflen, packet_data);
            break;

        case ETHERTYPE_IPV6:
            ts_parser_pkt_ipv6(buffer, bufflen, packet_data);
            break;

        case ETHERTYPE_VLAN_8021AD:
        case ETHERTYPE_VLAN:
            ts_parser_pkt_vlan(buffer, bufflen, packet_data);
            break;

        default:
            break;
    }
}