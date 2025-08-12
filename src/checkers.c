#include "checkers.h"
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
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/**
 * Compare mac addresses.
 *
 * @param buffer              full buffer, received from client
 * @param bufflen             size of buffer
 * @param mac                 mac address with which comparing
 *
 * @return                    true if addresses are same and false else
 */
bool
check_src_mac(char const *buffer, size_t bufflen, struct filter cur_filter)
{
    if (cur_filter.flags.src_mac_flag == 0)
        return true;
    struct ether_header const *const ether = (struct ether_header const*)buffer;
    uint8_t const* const addr = ether->ether_shost;
    return !memcmp(addr, cur_filter.src_mac.ether_addr_octet, ETHER_ADDR_LEN);
}

bool
check_dst_mac(char const *buffer, size_t bufflen, struct filter cur_filter)
{
    if (cur_filter.flags.dst_mac_flag == 0)
        return true;
    struct ether_header const *const ether = (struct ether_header const*)buffer;
    uint8_t const* const addr = ether->ether_dhost;
    return !memcmp(addr, cur_filter.dst_mac.ether_addr_octet, ETHER_ADDR_LEN);
}

/**
 * Check ether type are same or not.
 *
 * @param buffer              full buffer, received from client
 * @param bufflen             size of buffer
 * @param ether_type          ether type address with which comparing
 *
 * @return                    true if addresses are same and false else
 */
bool
check_ether_type(char const *buffer, size_t bufflen, struct filter cur_filter)
{
    if (cur_filter.flags.ether_type_flag == 0)
        return true;
    struct ether_header const *const ether = (struct ether_header const*)buffer;
    uint16_t ether_data = ether->ether_type;
    if(ether_data != cur_filter.ether_type)
    {
        DPRINTF("it is not  %u != %u\n", ntohs(ether_data), ntohs(cur_filter.ether_type));
        return false;
    }
    return true;
}

/**
 * Check ipv4 adderesses are same or not.
 *
 * @param buffer              full buffer, received from client
 * @param bufflen             size of buffer
 * @param ipv                 ipv4 address with which comparing
 *
 * @return                    true if addresses are same and false else
 */
bool
check_src_ipv4(char const *buffer, size_t bufflen,
    struct filter cur_filter)
{
    if (cur_filter.flags.dst_ipv4_flag == 0)
        return true;
    struct ether_header const *const ether = (struct ether_header const*)buffer;
    if (ether->ether_type == htons(ETHERTYPE_IP))
    {
        struct ip const *const ip_head = (struct ip const*)(buffer
            + sizeof(struct ether_header));
        if(ip_head->ip_src.s_addr == cur_filter.src_ipv4.s_addr)
        {
            DPRINTF("it is %s = %s\n", inet_ntoa(ip_head->ip_src),
                inet_ntoa(cur_filter.src_ipv4));
            return true;
        }
    }
    return false;
}

bool
check_dst_ipv4(char const *buffer, size_t bufflen,
    struct filter cur_filter)
{
    if (cur_filter.flags.dst_ipv4_flag == 0)
        return true;
    struct ether_header const *const ether = (struct ether_header const*)buffer;
    if (ether->ether_type == htons(ETHERTYPE_IP))
    {
        struct ip const *const ip_head = (struct ip const*)(buffer
            + sizeof(struct ether_header));
        if(ip_head->ip_dst.s_addr == cur_filter.dst_ipv4.s_addr)
        {
            DPRINTF("it is %s = %s\n", inet_ntoa(ip_head->ip_dst),
                inet_ntoa(cur_filter.dst_ipv4));
            return true;
        }
    }
    return false;
}

/**
 * Check ip protocols are same or not.
 *
 * @param buffer              full buffer, received from client
 * @param bufflen             size of buffer
 * @param cur_filter          current filter with which comparing
 *
 * @todo                      add ipv6
 *
 * @return                    true if protocols are same and false else
 */
bool
check_ip_protocol(char const *buffer, size_t bufflen,
    struct filter cur_filter)
{
    if (cur_filter.flags.ip_protocol_flag == 0)
        return true;
    struct ether_header const *const ether = (struct ether_header const*)buffer;
    if (ether->ether_type == htons(ETHERTYPE_IP))
    {
        struct ip const *const ip_head = (struct ip const*)(buffer
            + sizeof(struct ether_header));
        if( ip_head->ip_p == cur_filter.ip_protocol)
        {
            DPRINTF("ip protocol is suitable %u\n", ip_head->ip_p);
            return true;
        }
    }
    else if(ether->ether_type == htons(ETHERTYPE_IPV6))
        /* It is ipv6. Will be done later*/
        return false;
    return false;
}

/**
 * Check tcp ports are same or not.
 *
 * @param buffer              full buffer, received from client
 * @param bufflen             size of buffer
 * @param tcp_port            tcp port with which comparing
 * @param is_src              flag to indicate sourse or destination port*
 *
 * @todo                      add ipv6
 *
 * @return                    true if ports are same and false else
 */
bool
check_dst_tcp(char const *buffer, size_t bufflen,
    struct filter cur_filter)
{
    if (cur_filter.flags.dst_tcp_flag == 0)
        return true;
    struct ether_header const *const ether = (struct ether_header const*)buffer;
    if (ether->ether_type == htons(ETHERTYPE_IP))
    {
        struct ip const *const ip_head = (struct ip const*)(buffer
            + sizeof(struct ether_header));
        if (ip_head->ip_p == IPPROTO_TCP)
        {
            struct tcphdr *tcp = (struct tcphdr*)(buffer +
                ip_head->ip_hl*IHL_WORD_LEN + sizeof(struct ethhdr));
            if (tcp->th_dport == cur_filter.dst_tcp)
            {
                DPRINTF("tcp is suitable %u\n", ntohs(tcp->th_dport));
                return true;
            }
        }
        else
            /* IT is not tcp. */
            return false;
    }
    else if(ether->ether_type == htons(ETHERTYPE_IPV6))
        /* It is ipv6. Will be done later*/
        return false;
    return false;
}

bool
check_src_tcp(char const *buffer, size_t bufflen,
    struct filter cur_filter)
{
    if (cur_filter.flags.src_tcp_flag == 0)
        return true;
    struct ether_header const *const ether = (struct ether_header const*)buffer;
    if (ether->ether_type == htons(ETHERTYPE_IP))
    {
        struct ip const *const ip_head = (struct ip const*)(buffer
            + sizeof(struct ether_header));
        if (ip_head->ip_p == IPPROTO_TCP)
        {
            struct tcphdr *tcp = (struct tcphdr*)(buffer +
                ip_head->ip_hl*IHL_WORD_LEN + sizeof(struct ethhdr));
            if (tcp->th_sport == cur_filter.src_tcp)
            {
                DPRINTF("tcp is suitable %u\n", ntohs(tcp->th_sport));
                return true;
            }
        }
        else
            /* IT is not tcp. */
            return false;
    }
    else if(ether->ether_type == htons(ETHERTYPE_IPV6))
        /* It is ipv6. Will be done later*/
        return false;
    return false;
}


/**
 * Check udp ports are same or not.
 *
 * @param udp_port            udp port with which comparing
 * @param is_src              flag to indicate sourse or destination port
 *
 * @todo                      add ipv6
 *
 * @return                    true if ports are same and false else
 */
bool
check_dst_udp(char const *buffer, size_t bufflen,
    struct filter cur_filter)
{
    if (cur_filter.flags.dst_udp_flag == 0)
        return true;
    struct ether_header const *const ether = (struct ether_header const*)buffer;
    if (ether->ether_type == htons(ETHERTYPE_IP))
    {
        struct ip const *const ip_head = (struct ip const*)(buffer
            + sizeof(struct ether_header));
        if (ip_head->ip_p == IPPROTO_UDP)
        {
            struct udphdr *udp = (struct udphdr*)(buffer
                + ip_head->ip_hl*IHL_WORD_LEN + sizeof(struct ethhdr));
            if (udp->uh_dport == cur_filter.dst_udp)
            {
                DPRINTF("udp is suitable%u\n", ntohs(udp->uh_dport));
                return true;
            }
            else
                DPRINTF("udp not suit %u->%u\n",ntohs(udp->uh_dport),
                    ntohs(udp->uh_dport));
        }
        else
            /* It is not udp. */
            return false;
    }
    else if(ether->ether_type == htons(ETHERTYPE_IPV6))
        /* It is ipv6. Will be done later*/
        return false;
    return false;
}

bool
check_src_udp(char const *buffer, size_t bufflen,
    struct filter cur_filter)
{
    if (cur_filter.flags.src_udp_flag == 0)
        return true;
    struct ether_header const *const ether = (struct ether_header const*)buffer;
    if (ether->ether_type == htons(ETHERTYPE_IP))
    {
        struct ip const *const ip_head = (struct ip const*)(buffer
            + sizeof(struct ether_header));
        if (ip_head->ip_p == IPPROTO_UDP)
        {

            struct udphdr *udp = (struct udphdr*)(buffer
                + ip_head->ip_hl*IHL_WORD_LEN + sizeof(struct ethhdr));
            if (udp->uh_sport == cur_filter.src_udp)
            {
                DPRINTF("udp is suitable%u\n", ntohs(udp->uh_sport));
                return true;
            }
            else
                DPRINTF("udp not suit %u->%u\n",ntohs(udp->uh_sport),
                    ntohs(udp->uh_dport));
                return false;
        }
        else
            /* It is not udp. */
            return false;
    }
    else if(ether->ether_type == htons(ETHERTYPE_IPV6))
        /* It is ipv6. Will be done later*/
        return false;
    return false;
}