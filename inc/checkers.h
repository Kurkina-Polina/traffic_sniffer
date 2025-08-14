#ifndef CHECKERS_H
#define CHECKERS_H
#include "filter.h"
#include "definitions.h"
#include <stdbool.h>
#include <stddef.h>


bool
check_src_mac(struct filter packet_data, struct filter cur_filter);

bool
check_dst_mac(struct filter packet_data, struct filter cur_filter);

bool
check_ether_type(struct filter packet_data, struct filter cur_filter);

bool
check_src_ipv4(struct filter packet_data, struct filter cur_filter);

bool
check_dst_ipv4(struct filter packet_data, struct filter cur_filter);

bool
check_ip_protocol(struct filter packet_data, struct filter cur_filter);

bool
check_dst_tcp(struct filter packet_data, struct filter cur_filter);

bool
check_src_tcp(struct filter packet_data, struct filter cur_filter);

bool
check_dst_udp(struct filter packet_data, struct filter cur_filter);

bool
check_src_udp(struct filter packet_data, struct filter cur_filter);

bool
check_vlan_id(struct filter packet_data, struct filter cur_filter);

#endif