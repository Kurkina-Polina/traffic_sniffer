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
check_src_mac(struct filter packet_data, struct filter cur_filter)
{
    if (cur_filter.flags.src_mac_flag == 0)
        return true;
    //FIXME: add DPRINTF or remove везде and make
    // return packet_data.ether_type = cur_filter.ether_type
    return !memcmp(packet_data.src_mac.ether_addr_octet, cur_filter.src_mac.ether_addr_octet, ETHER_ADDR_LEN);
}

bool
check_dst_mac(struct filter packet_data, struct filter cur_filter)
{
    if (cur_filter.flags.dst_mac_flag == 0)
        return true;
    return !memcmp(packet_data.dst_mac.ether_addr_octet, cur_filter.dst_mac.ether_addr_octet, ETHER_ADDR_LEN);
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
check_ether_type(struct filter packet_data, struct filter cur_filter)
{
    if (cur_filter.flags.ether_type_flag == 0)
        return true;

    if(packet_data.ether_type == cur_filter.ether_type)
    {
        DPRINTF("it is 0x%04x == 0x%04x\n", ntohs(packet_data.ether_type), ntohs(cur_filter.ether_type));
        return true;
    }
    return false;
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
check_src_ipv4(struct filter packet_data, struct filter cur_filter)
{
    if (cur_filter.flags.src_ipv4_flag == 0)
        return true;
    if(packet_data.src_ipv4.s_addr == cur_filter.src_ipv4.s_addr)
    {
        DPRINTF("ip src is suitable %s == %s\n", inet_ntoa(packet_data.src_ipv4),
            inet_ntoa(cur_filter.src_ipv4));
        return true;
    }
    return false;
}

bool
check_dst_ipv4(struct filter packet_data, struct filter cur_filter)
{
    if (cur_filter.flags.dst_ipv4_flag == 0)
        return true;
    if(packet_data.dst_ipv4.s_addr == cur_filter.dst_ipv4.s_addr)
    {
        DPRINTF("ip dst is suitable %s == %s\n", inet_ntoa(packet_data.dst_ipv4),
            inet_ntoa(cur_filter.dst_ipv4));
        return true;
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
check_ip_protocol(struct filter packet_data, struct filter cur_filter)
{
    if (cur_filter.flags.ip_protocol_flag == 0)
        return true;
    if(packet_data.ip_protocol == cur_filter.ip_protocol)
    {
        DPRINTF("ip protocol is suitable %u == %u\n", packet_data.ip_protocol, cur_filter.ip_protocol);
        return true;
    }
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
check_dst_tcp(struct filter packet_data, struct filter cur_filter)
{
    if (cur_filter.flags.dst_tcp_flag == 0)
        return true;
    if (packet_data.dst_tcp == cur_filter.dst_tcp)
    {
        DPRINTF("tcp dst is suitable %u\n", ntohs(packet_data.dst_tcp));
        return true;
    }
    return false;
}

bool
check_src_tcp(struct filter packet_data, struct filter cur_filter)
{
    if (cur_filter.flags.src_tcp_flag == 0)
        return true;
    if (packet_data.src_tcp == cur_filter.src_tcp)
    {
        DPRINTF("tcp src is suitable %u\n", ntohs(packet_data.src_tcp));
        return true;
    }
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
check_dst_udp(struct filter packet_data, struct filter cur_filter)
{
    if (cur_filter.flags.dst_udp_flag == 0)
        return true;
    if (packet_data.dst_udp == cur_filter.dst_udp)
    {
        DPRINTF("udp dst is suitable %u\n", ntohs(packet_data.dst_udp));
        return true;
    }
    return false;
}

bool
check_src_udp(struct filter packet_data, struct filter cur_filter)
{
    if (cur_filter.flags.src_udp_flag == 0)
        return true;
    if (packet_data.src_udp == cur_filter.src_udp)
    {
        DPRINTF("udp src is suitable%u\n", ntohs(packet_data.src_udp));
        return true;
    }
    return false;
}

bool
check_vlan_id(struct filter packet_data, struct filter cur_filter)
{
    if (cur_filter.flags.vlan_id_flag == 0)
        return true;
    if (packet_data.vlan_id== cur_filter.vlan_id)
    {
        DPRINTF("vlan id is suitable%u\n", ntohs(packet_data.src_udp));
        return true;
    }
    return false;
}