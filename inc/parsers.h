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


/**
 * Parse dst mac from string val_key to field of struct new_filter.
 * If name_key is not dst_mac, skip.
 *
 * @param name_key             string of name key
 * @param val_key              string of value key
 * @param new_filter[out]      struct includes dst mac
 * @param message[out]         message about error
 *
 * @return                     true if success, false if fail
 *
 */
bool
parse_dst_mac(const char *name_key, const char *val_key, struct filter *new_filter, char *message);


/**
 * Parse srt mac from string val_key to field of struct new_filter.
 * If name_key is not src_mac, skip.
 *
 * @param name_key             string of name key
 * @param val_key              string of value key
 * @param new_filter[out]      struct includes src mac
 * @param message[out]         message about error
 *
 * @return                     true if success, false if fail
 *
 */
bool
parse_src_mac(const char *name_key, const char *val_key, struct filter *new_filter, char *message);


/**
 * Parse src ipv4 from string val_key to field of struct new_filter.
 * If name_key is not src ipv4, skip.
 *
 * @param name_key             string of name key
 * @param val_key              string of value key
 * @param new_filter[out]      struct includes src ipv4
 * @param message[out]         message about error
 *
 * @return                     true if success, false if fail
 *
 */
bool
parse_src_ipv4(const char *name_key, const char *val_key, struct filter *new_filter, char *message);


/**
 * Parse dst ipv4 from string val_key to field of struct new_filter.
 * If name_key is not dst ipv4, skip.
 *
 * @param name_key             string of name key
 * @param val_key              string of value key
 * @param new_filter[out]      struct includes dst ipv4
 * @param message[out]         message about error
 *
 * @return                     true if success, false if fail
 *
 */
bool
parse_dst_ipv4(const char *name_key, const char *val_key, struct filter *new_filter, char *message);


/**
 * Parse src ipv6 from string val_key to field of struct new_filter.
 * If name_key is not src ipv6, skip.
 *
 * @param name_key             string of name key
 * @param val_key              string of value key
 * @param new_filter[out]      struct includes src ipv6
 * @param message[out]         message about error
 *
 * @return                     true if success, false if fail
 *
 */
bool
parse_src_ipv6(const char *name_key, const char *val_key, struct filter *new_filter, char *message);

/**
 * Parse dst ipv6 from string val_key to field of struct new_filter.
 * If name_key is not dst ipv6, skip.
 *
 * @param name_key             string of name key
 * @param val_key              string of value key
 * @param new_filter[out]      struct includes dst ipv6
 * @param message[out]         message about error
 *
 * @return                     true if success, false if fail
 *
 */
bool
parse_dst_ipv6(const char *name_key, const char *val_key, struct filter *new_filter, char *message);


/**
 * Parse ip protocol from string val_key to field of struct new_filter.
 * If name_key is not ip protocol, skip.
 *
 * @param name_key             string of name key
 * @param val_key              string of value key
 * @param new_filter[out]      struct includes ip protocol
 * @param message[out]         message about error
 *
 * @return                     true if success, false if fail
 *
 */
bool
parse_ip_protocol(const char *name_key, const char *val_key, struct filter *new_filter, char *message);


/**
 * Parse ether type from string val_key to field of struct new_filter.
 * If name_key is not ether type, skip.
 *
 * @param name_key             string of name key
 * @param val_key              string of value key
 * @param new_filter[out]      struct includes ether type
 * @param message[out]         message about error
 *
 * @return                     true if success, false if fail
 *
 */
bool
parse_ether_type(const char *name_key, const char *val_key, struct filter *new_filter, char *message);


/**
 * Parse src tcp from string val_key to field of struct new_filter.
 * If name_key is not src tcp, skip.
 *
 * @param name_key             string of name key
 * @param val_key              string of value key
 * @param new_filter[out]      struct includes src tcp
 * @param message[out]         message about error
 *
 * @return                     true if success, false if fail
 *
 */
bool
parse_src_tcp(const char *name_key, const char *val_key, struct filter *new_filter, char *message);


/**
 * Parse dst tcp from string val_key to field of struct new_filter.
 * If name_key is not dst tcp, skip.
 *
 * @param name_key             string of name key
 * @param val_key              string of value key
 * @param new_filter[out]      struct includes dst tcp
 * @param message[out]         message about error
 *
 * @return                     true if success, false if fail
 *
 */
bool
parse_dst_tcp(const char *name_key, const char *val_key, struct filter *new_filter, char *message);


/**
 * Parse src udp from string val_key to field of struct new_filter.
 * If name_key is not src udp, skip.
 *
 * @param name_key             string of name key
 * @param val_key              string of value key
 * @param new_filter[out]      struct includes src udp
 * @param message[out]         message about error
 *
 * @return                     true if success, false if fail
 *
 */
bool
parse_src_udp(const char *name_key, const char *val_key, struct filter *new_filter, char *message);


/**
 * Parse dst udp from string val_key to field of struct new_filter.
 * If name_key is not dst udp, skip.
 *
 * @param name_key             string of name key
 * @param val_key              string of value key
 * @param new_filter[out]      struct includes dst udp
 * @param message[out]         message about error
 *
 * @return                     true if success, false if fail
 *
 */
bool
parse_dst_udp(const char *name_key, const char *val_key, struct filter *new_filter, char *message);


/**
 * Parse vlan id from string val_key to field of struct new_filter.
 * If name_key is not vlan id, skip.
 *
 * @param name_key             string of name key
 * @param val_key              string of value key
 * @param new_filter[out]      struct includes vlan id
 * @param message[out]         message about error
 *
 * @return                     true if success, false if fail
 *
 */
bool
parse_vlan_id(const char *name_key, const char *val_key, struct filter *new_filter, char *message);


/**
 * Parse interface from string val_key to field of struct new_filter.
 * If name_key is not interface, skip.
 *
 * @param name_key             string of name key
 * @param val_key              string of value key
 * @param new_filter[out]      struct includes interface
 * @param message[out]         message about error
 *
 * @return                     true if success, false if fail
 *
 */
bool
parse_interface(const char *name_key, const char *val_key, struct filter *new_filter, char *message);

#endif