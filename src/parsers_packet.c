#include "parsers_packet.h"

#include <string.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>

void
parse_packet_ipv4(char const *buffer, size_t bufflen, struct filter *packet_data)
{
    struct ip ip_head;
    memcpy(&ip_head, buffer, sizeof(struct ip));
    packet_data->src_ipv4 = ip_head.ip_src;
    packet_data->dst_ipv4 = ip_head.ip_dst;
    packet_data->ip_protocol = ip_head.ip_p;

    switch(ip_head.ip_p) {

        case IPPROTO_TCP:
            struct tcphdr tcp_head;
            memcpy(&tcp_head, buffer + ip_head.ip_hl*IHL_WORD_LEN, sizeof(struct tcphdr));
            packet_data->dst_tcp = tcp_head.th_dport;
            packet_data->src_tcp = tcp_head.th_sport;
            break;

        case IPPROTO_UDP:
            struct udphdr udp_head;
            memcpy(&udp_head, buffer + ip_head.ip_hl*IHL_WORD_LEN, sizeof(struct udphdr));
            packet_data->src_udp = udp_head.uh_sport;
            packet_data->dst_udp = udp_head.uh_dport;
            break;

        default:
            break;
    }
}

void
parse_packet_ipv6(char const *buffer, size_t bufflen, struct filter *packet_data);


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
            // parse_packet_ipv6(buffer, bufflen, packet_data);
            break;

        case ETHERTYPE_VLAN:
            parse_packet_vlan(buffer+sizeof(vlan_id)+sizeof(ether_type), bufflen-sizeof(uint16_t), packet_data);
            break;

        default:
            break;
    }
}

void
parse_packet_ether(char const *buffer, size_t bufflen, struct filter *packet_data)
{
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
            // parse_packet_ipv6(buffer, bufflen, packet_data);
            break;

        case ETHERTYPE_VLAN:
            parse_packet_vlan(buffer+sizeof(struct ether_header), bufflen-sizeof(struct ether_header), packet_data);
            break;

        default:
            break;
    }
}