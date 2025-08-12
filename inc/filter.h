#ifndef FILTER_H
#define FILTER_H
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
/* Flags indicating which filter types are active. */
struct filter_flag
{
    int vlan_id_flag : 1;     /* flag indicates vlan id is set */
    int dst_mac_flag : 1;     /* flag indicates destination mac address is set */
    int src_mac_flag : 1;     /* flag indicates source mac address is set */
    int ether_type_flag : 1;  /* flag indicates ether type is set */
    int dst_ipv4_flag : 1;    /* flag indicates destination ipv4 address is set */
    int src_ipv4_flag : 1;    /* flag indicates source ipv4 address is set */
    int dst_ipv6_flag : 1;    /* flag indicates destination ipv6 address is set */
    int src_ipv6_flag : 1;    /* flag indicates source ipv6 address is set */
    int ip_protocol_flag : 1; /* flag indicates ip protocol is set */
    int dst_tcp_flag : 1;     /* flag indicates destination tcp port is set */
    int src_tcp_flag : 1;     /* flag indicates source tcp port is set */
    int dst_udp_flag : 1;     /* flag indicates destination udp port is set */
    int src_udp_flag : 1;     /* flag indicates destination udp port is set */
};

/* Filter contains or not keys. */
struct filter
{
    struct in6_addr dst_ipv6; /* destination ip version 6*/
    struct in6_addr src_ipv6; /* sourse ip version 6*/

    struct filter_flag flags; /* flags indicating what filters are set */

    size_t size;              /* overall size of all packets, suiting filter */
    size_t count_packets;     /* count of packets that have same filter */

    struct in_addr dst_ipv4;  /* destination ip version 4*/
    struct in_addr src_ipv4;  /* sourse ip version 4*/

    struct ether_addr dst_mac;/* destination mac address */
    struct ether_addr src_mac;/* sourse mac address */
    uint16_t vlan_id;         /* vlan id */
    uint16_t ether_type;      /* ether type */
    uint16_t dst_tcp;         /* destination tcp port*/
    uint16_t src_tcp;         /* sourse tcp port */
    uint16_t dst_udp;         /* destination udp port */
    uint16_t src_udp;         /* source udp port */
    uint8_t ip_protocol;      /* ip protocol */
};
#endif