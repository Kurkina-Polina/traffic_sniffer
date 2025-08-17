#include "parsers_packet.h"

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

void
parse_packet_tcp(char const *buffer, size_t bufflen, struct filter *packet_data)
{
    struct tcphdr tcp_head;
    memcpy(&tcp_head, buffer, sizeof(struct tcphdr));
    packet_data->dst_tcp = tcp_head.th_dport;
    packet_data->src_tcp = tcp_head.th_sport;
}

void
parse_packet_udp(char const *buffer, size_t bufflen, struct filter *packet_data)
{
    struct udphdr udp_head;
    memcpy(&udp_head, buffer, sizeof(struct udphdr));
    packet_data->src_udp = udp_head.uh_sport;
    packet_data->dst_udp = udp_head.uh_dport;
}

void
parse_packet_ipv4(char const *buffer, size_t bufflen, struct filter *packet_data)
{
    struct ip ip_head;
    memcpy(&ip_head, buffer, sizeof(struct ip));
    packet_data->src_ipv4 = ip_head.ip_src;
    packet_data->dst_ipv4 = ip_head.ip_dst;
    packet_data->ip_protocol = ip_head.ip_p;

    switch(ip_head.ip_p)
    {
        case IPPROTO_TCP:
            parse_packet_tcp(buffer + ip_head.ip_hl * IHL_WORD_LEN, bufflen - ip_head.ip_hl * IHL_WORD_LEN, packet_data);
            break;

        case IPPROTO_UDP:
            parse_packet_udp(buffer + ip_head.ip_hl * IHL_WORD_LEN, bufflen - ip_head.ip_hl * IHL_WORD_LEN, packet_data);
            break;

        default:
            break;
    }
}

void
parse_packet_ipv6(char const *buffer, size_t bufflen, struct filter *packet_data){
    struct ip6_hdr  ip6_head;
    memcpy(&ip6_head, buffer, sizeof(struct ip6_hdr));
    packet_data->src_ipv6 = ip6_head.ip6_src;
    packet_data->dst_ipv6 = ip6_head.ip6_dst;
    packet_data->ip_protocol = ip6_head.ip6_ctlun.ip6_un1.ip6_un1_nxt;

    size_t offset = sizeof(struct ip6_hdr);
    static const int IP6_HEADER_UNIT_SIZE = 8;


    uint8_t next_header = ip6_head.ip6_ctlun.ip6_un1.ip6_un1_nxt;
    while (offset < bufflen) {
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
                    parse_packet_tcp(buffer + offset, bufflen - offset, packet_data);
                }
                return;
            case IPPROTO_UDP:
                if (offset + sizeof(struct udphdr) <= bufflen) {
                    parse_packet_udp(buffer + offset, bufflen - offset, packet_data);
                }
                return;
            default:
                return; /* unknown protocol */
        }
    }
}


//buffer это указатель уже на начало данных откуда надо начать читать
void
parse_packet_vlan(char const *buffer, size_t bufflen, struct filter *packet_data)
{
    uint16_t vlan_tci;
    memcpy(&vlan_tci, buffer, sizeof(uint16_t));

    uint16_t vlan_id = ntohs(vlan_tci) & 0x0FFF;
    if (packet_data->vlan_id == 0)
        packet_data->vlan_id = vlan_id;

    uint16_t ether_type;
    memcpy(&ether_type, buffer+sizeof(uint16_t), sizeof(uint16_t));
    packet_data->ether_type = ether_type;
    switch(ntohs(ether_type))
    {
        case ETHERTYPE_IP:
            parse_packet_ipv4(buffer+sizeof(vlan_id)+sizeof(ether_type), bufflen-sizeof(uint16_t), packet_data);
            break;

        case ETHERTYPE_IPV6:
            parse_packet_ipv6(buffer+sizeof(vlan_id)+sizeof(ether_type), bufflen-sizeof(uint16_t), packet_data);
            break;

        case ETHERTYPE_VLAN:
            parse_packet_vlan(buffer+sizeof(vlan_id)+sizeof(ether_type), bufflen-sizeof(uint16_t), packet_data);
            break;

        default:
            break;
    }
}

void
parse_packet_ether(char const *buffer, size_t bufflen, struct filter *packet_data, struct sockaddr_ll sniffaddr)
{
    packet_data->interface = sniffaddr.sll_ifindex;

    struct ether_header ether_head;
    memcpy(&ether_head, buffer, sizeof(ether_head));
    // FIXME: в теории можно заменить на обычное присваивание
    // тк структура запакованная и они одинаковые, но насколько это важно не знаю
    memcpy(&(packet_data->dst_mac), &(ether_head.ether_dhost), sizeof(struct ether_addr));
    memcpy(&(packet_data->src_mac), &(ether_head.ether_shost), sizeof(struct ether_addr));
    packet_data->ether_type = ether_head.ether_type;

    switch(ntohs(ether_head.ether_type))
    {
        case ETHERTYPE_IP:
            parse_packet_ipv4(buffer+sizeof(struct ether_header), bufflen-sizeof(struct ether_header), packet_data);
            break;

        case ETHERTYPE_IPV6:
            parse_packet_ipv6(buffer+sizeof(struct ether_header), bufflen-sizeof(struct ether_header), packet_data);
            break;

        case ETHERTYPE_VLAN:
            parse_packet_vlan(buffer+sizeof(struct ether_header), bufflen-sizeof(struct ether_header), packet_data);
            break;

        default:
            break;
    }
}