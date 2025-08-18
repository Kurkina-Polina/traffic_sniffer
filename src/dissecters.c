#include "dissecters.h"

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
dissect_tcp(char const *buffer, size_t bufflen, struct filter *packet_data)
{
    struct tcphdr tcp_head;
    //FIXME: add this check
    if (bufflen < sizeof(tcp_head))
        return;
    memcpy(&tcp_head, buffer, sizeof(tcp_head));
    packet_data->dst_tcp = tcp_head.th_dport;
    packet_data->src_tcp = tcp_head.th_sport;
}

void
dissect_udp(char const *buffer, size_t bufflen, struct filter *packet_data)
{
    struct udphdr udp_head;
    memcpy(&udp_head, buffer, sizeof(udp_head));
    packet_data->src_udp = udp_head.uh_sport;
    packet_data->dst_udp = udp_head.uh_dport;
}

void
dissect_ipv4(char const *buffer, size_t bufflen, struct filter *packet_data)
{
    struct ip ip_head;
    memcpy(&ip_head, buffer, sizeof(ip_head));
    packet_data->src_ipv4 = ip_head.ip_src;
    packet_data->dst_ipv4 = ip_head.ip_dst;
    packet_data->ip_protocol = ip_head.ip_p;

    // FIXME: do the same with ptr and size as done in ether
    switch(ip_head.ip_p)
    {
        case IPPROTO_TCP:
            dissect_tcp(buffer + ip_head.ip_hl * IHL_WORD_LEN, bufflen - ip_head.ip_hl * IHL_WORD_LEN, packet_data);
            break;

        case IPPROTO_UDP:
            dissect_udp(buffer + ip_head.ip_hl * IHL_WORD_LEN, bufflen - ip_head.ip_hl * IHL_WORD_LEN, packet_data);
            break;

        default:
            break;
    }
}

void
dissect_ipv6(char const *buffer, size_t bufflen, struct filter *packet_data){
    struct ip6_hdr  ip6_head;
    memcpy(&ip6_head, buffer, sizeof(struct ip6_hdr));
    packet_data->src_ipv6 = ip6_head.ip6_src;
    packet_data->dst_ipv6 = ip6_head.ip6_dst;
    packet_data->ip_protocol = ip6_head.ip6_ctlun.ip6_un1.ip6_un1_nxt;

    size_t offset = sizeof(struct ip6_hdr); /* counting start the next head */
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
                //FIXME : copy past buffer + offset
                memcpy(&ext, buffer + offset, sizeof(struct ip6_ext));
                next_header = ext.ip6e_nxt;
                offset += (ext.ip6e_len + 1) * IP6_HEADER_UNIT_SIZE; // FIXME: what is +1?
                break;
            }
            case IPPROTO_TCP:
                if (offset + sizeof(struct tcphdr) <= bufflen) {
                    dissect_tcp(buffer + offset, bufflen - offset, packet_data);
                }
                return;
            case IPPROTO_UDP:
                if (offset + sizeof(struct udphdr) <= bufflen) {
                    dissect_udp(buffer + offset, bufflen - offset, packet_data);
                }
                return;
            default:
                return; /* unknown protocol */
        }
    }
}



//FIXME: squash switch with dissect_ether
void
dissect_vlan(char const *buffer, size_t bufflen, struct filter *packet_data)
{
    //FIXME:
    char const* ptr = buffer;
    uint16_t vlan_tci;
    memcpy(&vlan_tci, ptr, sizeof(uint16_t));
    ptr += sizeof(vlan_tci);

    uint16_t vlan_id = ntohs(vlan_tci) & 0x0FFF; //FIXME: add MASK define
    if (packet_data->vlan_id == 0)
        packet_data->vlan_id = vlan_id;

    uint16_t ether_type;
    memcpy(&ether_type, ptr, sizeof(ether_type));
    ptr += sizeof(ether_type);
    packet_data->ether_type = ether_type;
    size_t const l2_len = bufflen - (sizeof(ether_type) + sizeof(vlan_tci)); // FIXME:
    switch(ntohs(ether_type))
    {
        case ETHERTYPE_IP:
            dissect_ipv4(ptr, l2_len, packet_data);
            break;

        case ETHERTYPE_IPV6:
            dissect_ipv6(ptr, l2_len, packet_data);
            break;

        case ETHERTYPE_VLAN:
            dissect_vlan(ptr, l2_len, packet_data);
            break;

        default:
            break;
    }
}

void
dissect_ether(char const *buffer, size_t bufflen, struct filter *packet_data, struct sockaddr_ll sniffaddr)
{
    packet_data->interface = sniffaddr.sll_ifindex;

    struct ether_header ether_head;
    memcpy(&ether_head, buffer, sizeof(ether_head));
    memcpy(&(packet_data->dst_mac), &(ether_head.ether_dhost), sizeof(struct ether_addr));
    memcpy(&(packet_data->src_mac), &(ether_head.ether_shost), sizeof(struct ether_addr));
    packet_data->ether_type = ether_head.ether_type;

    char const* l3_header_ptr = buffer + sizeof(ether_head);
    size_t const l3_header_len = bufflen - sizeof(ether_head);
    switch (ntohs(ether_head.ether_type))
    {
        case ETHERTYPE_IP:
            dissect_ipv4(l3_header_ptr, l3_header_len, packet_data);
            break;

        case ETHERTYPE_IPV6:
            dissect_ipv6(l3_header_ptr, l3_header_len, packet_data);
            break;

        case ETHERTYPE_VLAN:
            dissect_vlan(l3_header_ptr, l3_header_len, packet_data);
            break;

        default:
            break;
    }
}