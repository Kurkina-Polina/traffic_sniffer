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

/* Compare sourse mac addresses. */
bool
check_src_mac(const struct filter *packet_data, const struct filter *cur_filter)
{
    if (!cur_filter->flags.src_mac_flag)
        return true;
    if (memcmp(packet_data->src_mac.ether_addr_octet,
        cur_filter->src_mac.ether_addr_octet, ETHER_ADDR_LEN) == 0)
    {
        DPRINTF("src mac is suit\n");
        return true;
    }
    return false;
}

/* Compare destination mac addresses. */
bool
check_dst_mac(const struct filter *packet_data, const struct filter *cur_filter)
{
    if (!cur_filter->flags.dst_mac_flag)
        return true;
    if (memcmp(packet_data->dst_mac.ether_addr_octet,
        cur_filter->dst_mac.ether_addr_octet, ETHER_ADDR_LEN))
    {
        DPRINTF("dst mac is suit\n");
        return true;
    }
    return false;
}

/* Compare ether_types. */
bool
check_ether_type(const struct filter *packet_data, const struct filter *cur_filter)
{
    if (!cur_filter->flags.ether_type_flag)
        return true;

    if(packet_data->ether_type == cur_filter->ether_type)
    {
        DPRINTF("ether type is suit: 0x%04x == 0x%04x\n",
            ntohs(packet_data->ether_type), ntohs(cur_filter->ether_type));
        return true;
    }
    return false;
}

/* Compare src_ipv4. */
bool
check_src_ipv4(const struct filter *packet_data, const struct filter *cur_filter)
{
    if (!cur_filter->flags.src_ipv4_flag)
        return true;
    if(packet_data->src_ipv4.s_addr == cur_filter->src_ipv4.s_addr)
    {
        DPRINTF("ip src is suit %s == %s\n", inet_ntoa(packet_data->src_ipv4),
            inet_ntoa(cur_filter->src_ipv4));
        return true;
    }
    return false;
}

/* Compare dst_ipv4. */
bool
check_dst_ipv4(const struct filter *packet_data, const struct filter *cur_filter)
{
    if (!cur_filter->flags.dst_ipv4_flag)
        return true;
    if(packet_data->dst_ipv4.s_addr == cur_filter->dst_ipv4.s_addr)
    {
        DPRINTF("ip dst is suit %s == %s\n", inet_ntoa(packet_data->dst_ipv4),
            inet_ntoa(cur_filter->dst_ipv4));
        return true;
    }
    return false;
}

/* Compare src_ipv6. */
bool
check_src_ipv6(const struct filter *packet_data, const struct filter *cur_filter)
{
    if (!cur_filter->flags.src_ipv6_flag)
        return true;
    if (memcmp(&packet_data->src_ipv6, &cur_filter->src_ipv6, sizeof(struct in6_addr)) == 0)
    {
        DPRINTF("ipv6 src is suit\n");
        return true;
    }
    return false;
}

/* Compare dst_ipv6. */
bool
check_dst_ipv6(const struct filter *packet_data, const struct filter *cur_filter)
{
    if (!cur_filter->flags.dst_ipv6_flag)
        return true;
    if (memcmp(&packet_data->dst_ipv6, &cur_filter->dst_ipv6, sizeof(struct in6_addr)) == 0)
    {
        DPRINTF("ipv6 dst is suitable\n");
        return true;
    }
    return false;
}

/* Compare ip_protocol. */
bool
check_ip_protocol(const struct filter *packet_data, const struct filter *cur_filter)
{
    if (!cur_filter->flags.ip_protocol_flag)
        return true;
    if(packet_data->ip_protocol == cur_filter->ip_protocol)
    {
        DPRINTF("ip protocol is suitable %u == %u\n",
            packet_data->ip_protocol, cur_filter->ip_protocol);
        return true;
    }
    return false;
}

/* Compare dst_tcp. */
bool
check_dst_tcp(const struct filter *packet_data, const struct filter *cur_filter)
{
    if (!cur_filter->flags.dst_tcp_flag)
        return true;
    if (packet_data->dst_tcp == cur_filter->dst_tcp)
    {
        DPRINTF("tcp dst is suit %u\n", ntohs(packet_data->dst_tcp));
        return true;
    }
    return false;
}

/* Compare src_tcp. */
bool
check_src_tcp(const struct filter *packet_data, const struct filter *cur_filter)
{
    if (!cur_filter->flags.src_tcp_flag)
        return true;
    if (packet_data->src_tcp == cur_filter->src_tcp)
    {
        DPRINTF("tcp src is suit %u\n", ntohs(packet_data->src_tcp));
        return true;
    }
    return false;
}

/* Compare dst_udp. */
bool
check_dst_udp(const struct filter *packet_data, const struct filter *cur_filter)
{
    if (!cur_filter->flags.dst_udp_flag)
        return true;
    if (packet_data->dst_udp == cur_filter->dst_udp)
    {
        DPRINTF("udp dst is suit %u\n", ntohs(packet_data->dst_udp));
        return true;
    }
    return false;
}

/* Compare src_udp. */
bool
check_src_udp(const struct filter *packet_data, const struct filter *cur_filter)
{
    if (!cur_filter->flags.src_udp_flag)
        return true;
    if (packet_data->src_udp == cur_filter->src_udp)
    {
        DPRINTF("udp src is suit %u\n", ntohs(packet_data->src_udp));
        return true;
    }
    return false;
}

/* Compare vlan_id. */
bool
check_vlan_id(const struct filter *packet_data, const struct filter *cur_filter)
{
    if (!cur_filter->flags.vlan_id_flag)
        return true;
    if (packet_data->vlan_id == cur_filter->vlan_id)
    {
        DPRINTF("vlan id is suit %u\n", packet_data->vlan_id);
        return true;
    }
    return false;
}

/* Compare interfaces. */
bool
check_interface(const struct filter *packet_data, const struct filter *cur_filter)
{
    if (!cur_filter->flags.interface_flag)
        return true;
    if (packet_data->interface == cur_filter->interface)
    {
        DPRINTF("interface is suit %u\n", packet_data->interface);
        return true;
    }
    return false;
}