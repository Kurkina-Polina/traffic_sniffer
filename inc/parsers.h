#ifndef PARSERS_H
#define PARSERS_H
#include <stdbool.h>
#include "definitions.h"
#include "filter.h"

/**
 * Parse MAC address from string to struct of ether header.
 *
 * @param str                  string contain mac address
 * @param mac[out]             parsed mac address
 *
 */
bool
parse_mac(const char *str, struct ether_addr *mac);

bool
parse_src_ipv4(const char *name_key, const char *val_key, struct filter *new_filter, char *message);
bool
parse_dst_ipv4(const char *name_key, const char *val_key, struct filter *new_filter, char *message);

bool
parse_dst_mac(const char *name_key, const char *val_key, struct filter *new_filter, char *message);
bool
parse_src_mac(const char *name_key, const char *val_key, struct filter *new_filter, char *message);
bool
parse_ip_protocol(const char *name_key, const char *val_key, struct filter *new_filter, char *message);

bool
parse_ether_type(const char *name_key, const char *val_key, struct filter *new_filter, char *message);

bool
parse_src_tcp(const char *name_key, const char *val_key, struct filter *new_filter, char *message);

bool
parse_dst_tcp(const char *name_key, const char *val_key, struct filter *new_filter, char *message);

bool
parse_src_udp(const char *name_key, const char *val_key, struct filter *new_filter, char *message);

bool
parse_dst_udp(const char *name_key, const char *val_key, struct filter *new_filter, char *message);

bool
parse_vlan_id(const char *name_key, const char *val_key, struct filter *new_filter, char *message);

bool
parse_interface(const char *name_key, const char *val_key, struct filter *new_filter, char *message);

#endif