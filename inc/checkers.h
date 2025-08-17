#ifndef CHECKERS_H
#define CHECKERS_H
#include "filter.h"
#include "definitions.h"
#include <stdbool.h>
#include <stddef.h>


bool
check_src_mac(const struct filter packet_data, const struct filter cur_filter);

bool
check_dst_mac(const struct filter packet_data, const struct filter cur_filter);

bool
check_ether_type(const struct filter packet_data, const struct filter cur_filter);

bool
check_src_ipv4(const struct filter packet_data, const struct filter cur_filter);

bool
check_dst_ipv4(const struct filter packet_data, const struct filter cur_filter);

bool
check_src_ipv6(const struct filter packet_data, const struct filter cur_filter);

bool
check_dst_ipv6(const struct filter packet_data, const struct filter cur_filter);

bool
check_ip_protocol(const struct filter packet_data, const struct filter cur_filter);

bool
check_dst_tcp(const struct filter packet_data, const struct filter cur_filter);

bool
check_src_tcp(const struct filter packet_data, const struct filter cur_filter);

bool
check_dst_udp(const struct filter packet_data, const struct filter cur_filter);

bool
check_src_udp(const struct filter packet_data, const struct filter cur_filter);

bool
check_vlan_id(const struct filter packet_data, const struct filter cur_filter);

bool
check_interface(const struct filter packet_data, const struct filter cur_filter);

#endif