#ifndef CHECKERS_H
#define CHECKERS_H
#include "filter.h"
#include "definitions.h"
#include <stdbool.h>
#include <stddef.h>

/**
 * Compare sourse mac addresses.
 *
 * @param packet_data         packet data with mac address
 * @param cur_filter          current filter with mac address
 *
 * @return                    true if addresses are same and false else
 */
extern bool
check_src_mac(const struct filter *packet_data, const struct filter *cur_filter);


/**
 * Compare destination mac addresses.
 *
 * @param packet_data         packet data with mac address
 * @param cur_filter          current filter with mac address
 *
 * @return                    true if addresses are same and false else
 */
extern bool
check_dst_mac(const struct filter *packet_data, const struct filter *cur_filter);


/**
 * Compare ether types.
 *
 * @param packet_data         packet data with ether type
 * @param cur_filter          current filter with ether type
 *
 * @return                    true if addresses are same and false else
 */
extern bool
check_ether_type(const struct filter *packet_data, const struct filter *cur_filter);


/**
 * Compare sourse ipv4 addresses.
 *
 * @param packet_data         packet data with ipv4 address
 * @param cur_filter          current filter with ipv4 address
 *
 * @return                    true if addresses are same and false else
 */
extern bool
check_src_ipv4(const struct filter *packet_data, const struct filter *cur_filter);


/**
 * Compare destination ipv4 addresses.
 *
 * @param packet_data         packet data with ipv4 address
 * @param cur_filter          current filter with ipv4 address
 *
 * @return                    true if addresses are same and false else
 */
extern bool
check_dst_ipv4(const struct filter *packet_data, const struct filter *cur_filter);


/**
 * Compare sourse ipv6 addresses.
 *
 * @param packet_data         packet data with ipv6 address
 * @param cur_filter          current filter with ipv6 address
 *
 * @return                    true if addresses are same and false else
 */
extern bool
check_src_ipv6(const struct filter *packet_data, const struct filter *cur_filter);


/**
 * Compare destination ipv6 addresses.
 *
 * @param packet_data         packet data with ipv6 address
 * @param cur_filter          current filter with ipv6 address
 *
 * @return                    true if addresses are same and false else
 */
extern bool
check_dst_ipv6(const struct filter *packet_data, const struct filter *cur_filter);


/**
 * Compare ip protocols.
 *
 * @param packet_data         packet data with ip protocol
 * @param cur_filter          current filter withip protocol
 *
 * @return                    true if addresses are same and false else
 */
extern bool
check_ip_protocol(const struct filter *packet_data, const struct filter *cur_filter);


/**
 * Compare destination tcp port.
 *
 * @param packet_data         packet data with tcp ports
 * @param cur_filter          current filter with tcp ports
 *
 * @return                    true if addresses are same and false else
 */
extern bool
check_dst_tcp(const struct filter *packet_data, const struct filter *cur_filter);


/**
 * Compare sourse tcp port.
 *
 * @param packet_data         packet data with tcp port
 * @param cur_filter          current filter with tcp port
 *
 * @return                    true if addresses are same and false else
 */
extern bool
check_src_tcp(const struct filter *packet_data, const struct filter *cur_filter);


/**
 * Compare  destination udp port.
 *
 * @param packet_data         packet data with  destination udp port
 * @param cur_filter          current filter with  destination udp port
 *
 * @return                    true if addresses are same and false else
 */
extern bool
check_dst_udp(const struct filter *packet_data, const struct filter *cur_filter);


/**
 * Compare sourse udp port.
 *
 * @param packet_data         packet data with udp port
 * @param cur_filter          current filter with udp port
 *
 * @return                    true if addresses are same and false else
 */
extern bool
check_src_udp(const struct filter *packet_data, const struct filter *cur_filter);


/**
 * Compare vlan id.
 *
 * @param packet_data         packet data with vlan id
 * @param cur_filter          current filter with vlan id
 *
 * @return                    true if addresses are same and false else
 */
extern bool
check_vlan_id(const struct filter *packet_data, const struct filter *cur_filter);


/**
 * Compare interfaces.
 *
 * @param packet_data         packet data with interfaces
 * @param cur_filter          current filter with interfaces
 *
 * @return                    true if addresses are same and false else
 */
extern bool
check_interface(const struct filter *packet_data, const struct filter *cur_filter);

#endif