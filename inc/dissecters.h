#ifndef DISSECTERS_h
#define DISSECTERS_h
#include "filter.h"
#include "definitions.h"
#include <linux/if_packet.h>

/**
 * Dissect tcp header and fill packet_data with dst_tcp and src_tcp.
 *
 * @param buffer               pointer to start of tcp header
 * @param bufflen              remaining len of packet (tcp header + payload)
 * @param packet_data          data of a packet
 *
 */
extern void
dissect_tcp(char const *buffer, size_t bufflen, struct filter *packet_data);


/**
 * Dissect udp header and fill packet_data with dst_udp and src_udp.
 *
 * @param buffer               pointer to start of udp header
 * @param bufflen              remaining len of packet (udp header + payload)
 * @param packet_data          data of a packet
 *
 */
extern void
dissect_udp(char const *buffer, size_t bufflen, struct filter *packet_data);


/**
 * Dissect ipv4 header and fill packet_data with dst_ipv4, src_ipv4, ip_protocol.
 *
 * @param buffer               pointer to start of ipv4 header
 * @param bufflen              remaining len of packet (ipv4 header + payload)
 * @param packet_data          data of a packet
 *
 */
extern void
dissect_ipv4(char const *buffer, size_t bufflen, struct filter *packet_data);


/**
 * Dissect ipv6 header and fill dst_ipv6, src_ipv6, ip_protocol.
 *
 * @param buffer               pointer to start of ipv6 header
 * @param bufflen              remaining len of packet (ipv6 header + payload)
 * @param packet_data          data of a packet
 *
 */
extern void
dissect_ipv6(char const *buffer, size_t bufflen, struct filter *packet_data);


/**
 * Dissect vlan header and fill packet_data with vlan_id.
 *
 * @param buffer               pointer to start of vlan header
 * @param bufflen              remaining len of packet (vlan header + payload)
 * @param packet_data          data of a packet
 *
 */
extern void
dissect_vlan(char const *buffer, size_t bufflen, struct filter *packet_data);


/**
 * Dissect ether header and fill packet_data with dst_mac, src_mac,
 * interface, ether_type.
 *
 * @param buffer               pointer to start of ether header
 * @param bufflen              remaining len of packet (ether header + payload)
 * @param packet_data          data of a packet
 *
 */
extern void
dissect_ether(char const *buffer, size_t bufflen, struct filter *packet_data, struct sockaddr_ll sniffaddr);
#endif