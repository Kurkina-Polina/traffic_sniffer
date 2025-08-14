#ifndef PARSERS_PACKET_H
#define PARSERS_PACKET_H
#include "filter.h"
#include "definitions.h"
void
parse_packet_ipv4(char const *buffer, size_t bufflen, struct filter *packet_data);

void
parse_packet_ipv6(char const *buffer, size_t bufflen, struct filter *packet_data);

void
parse_packet_vlan(char const *buffer, size_t bufflen, struct filter *packet_data);

void
parse_packet_ether(char const *buffer, size_t bufflen, struct filter *packet_data);
#endif