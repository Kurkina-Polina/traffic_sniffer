/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2022 OKTET Labs Ltd. All rights reserved. */
/** @file
 * @brief Key parsers for string-to-filter conversion.
 *
 * Extracts and validates filter parameters from input strings.
 */

#include "parsers.h"
#include <arpa/inet.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <net/if.h>
#include <errno.h>

/* Parse MAC address from string to struct of ether header. */
bool
parse_mac(const char *str, struct ether_addr *mac)
{
    return sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                 &mac->ether_addr_octet[0], &mac->ether_addr_octet[1],
                 &mac->ether_addr_octet[2], &mac->ether_addr_octet[3],
                 &mac->ether_addr_octet[4], &mac->ether_addr_octet[5]) == 6;
}

/* Parse dst mac from string val_key to field of struct new_filter. */
bool
parse_dst_mac(const char *name_key, const char *val_key,
    struct filter *new_filter, char *message, size_t message_len)
{
    if (strcmp(name_key, "dst_mac") != 0)
        return true;
    if (new_filter->flags.dst_mac_flag)
    {
        strncpy(message, "Error: dst mac is set already \n", message_len);
        return false;
    }
    if (!parse_mac(val_key, &new_filter->dst_mac))
    {
        strncpy(message, "Error: filter dst_mac \n", message_len);
        return false;
    }
    new_filter->flags.dst_mac_flag = true;
    return true;
}


/* Parse src mac from string val_key to field of struct new_filter. */
bool
parse_src_mac(const char *name_key, const char *val_key,
    struct filter *new_filter, char *message, size_t message_len)
{
    if (strcmp(name_key, "src_mac") != 0)
        return true;
    if (new_filter->flags.src_mac_flag) {
        strncpy(message, "Error: src mac is set already \n", message_len);
        return false;
    }
    if (!parse_mac(val_key, &new_filter->src_mac))
    {
        strncpy(message, "Error: filter src_mac \n", message_len);
        return false;
    }
    new_filter->flags.src_mac_flag = true;
    return true;
}


/* Parse src ipv4 from string val_key to field of struct new_filter. */
bool
parse_src_ipv4(const char *name_key, const char *val_key,
    struct filter *new_filter, char *message, size_t message_len)
{
    int rc; /* returned code by inet_pton() */

    if (strcmp(name_key, "src_ipv4") != 0)
        return true;
    if (new_filter->flags.src_ipv4_flag)
    {
        strncpy(message, "Error: src ipv4 is set already \n", message_len);
        return false;
    }
    rc = inet_pton(AF_INET, val_key, &(new_filter->src_ipv4));
    if (rc <= 0) {
        printf("error: Not in presentation format");
        printf("%s|%s\n",
            val_key, inet_ntoa(new_filter->src_ipv4));
        strncpy(message, "Error: filter src_ipv4: not in presentation format\n",message_len);
        return false;
    }
    new_filter->flags.src_ipv4_flag = true;
    return true;
}


/* Parse dst ipv4 from string val_key to field of struct new_filter. */
bool
parse_dst_ipv4(const char *name_key, const char *val_key,
    struct filter *new_filter, char *message, size_t message_len)
{
    int rc; /* returned code by inet_pton() */

    if (strcmp(name_key, "dst_ipv4") != 0)
        return true;
    if (new_filter->flags.dst_ipv4_flag)
    {
        strncpy(message, "Error: dst ipv4 is set already \n", message_len);
        return false;
    }
    rc = inet_pton(AF_INET, val_key, &(new_filter->dst_ipv4));
    if (rc <= 0) {
        printf("error: Not in presentation format");
        printf("%s|%s\n",
            val_key, inet_ntoa(new_filter->dst_ipv4));
        strncpy(message, "Error: filter dst_ipv4: not in presentation format\n", message_len);
        return false;
    }
    new_filter->flags.dst_ipv4_flag = true;
    return true;
}


/* Parse src ipv6 from string val_key to field of struct new_filter. */
bool
parse_src_ipv6(const char *name_key, const char *val_key,
    struct filter *new_filter, char *message, size_t message_len)
{
    int rc; /* returned code by inet_pton() */

    if (strcmp(name_key, "src_ipv6") != 0)
        return true;
    if (new_filter->flags.src_ipv6_flag)
    {
        strncpy(message, "Error: src ipv6 is set already \n", message_len);
        return false;
    }
    rc = inet_pton(AF_INET6, val_key, &(new_filter->src_ipv6));
    if (rc <= 0) {
        printf("error: Not in presentation format");
        printf("|%s|\n",val_key);
        strncpy(message, "Error: filter src_ipv6: not in presentation format\n", message_len);
        return false;
    }
    new_filter->flags.src_ipv6_flag = 1;
    return true;
}


/* Parse dst ipv6 from string val_key to field of struct new_filter. */
bool
parse_dst_ipv6(const char *name_key, const char *val_key,
    struct filter *new_filter, char *message, size_t message_len)
{
    int rc; /* returned code by inet_pton() */

    if (strcmp(name_key, "dst_ipv6") != 0)
        return true;
    if (new_filter->flags.dst_ipv6_flag)
    {
        strncpy(message, "Error: dst ipv6 is set already \n", message_len);
        return false;
    }
    rc = inet_pton(AF_INET6, val_key, &(new_filter->dst_ipv6));
    if (rc <= 0) {
        printf("error: Not in presentation format");
        printf("|%s|\n",val_key);
        strncpy(message, "Error: filter dst_ipv6: not in presentation format\n", message_len);
        return false;
    }
    new_filter->flags.dst_ipv6_flag = 1;
    return true;
}


/* Parse ip protocol from string val_key to field of struct new_filter. */
bool
parse_ip_protocol(const char *name_key, const char *val_key,
    struct filter *new_filter, char *message, size_t message_len)
{
    uint8_t ip_protocol;

    if (strcmp(name_key, "ip_protocol") != 0)
        return true;
    if (new_filter->flags.ip_protocol_flag)
    {
        strncpy(message, "Error: ip protocol is set already \n", message_len);
        return false;
    }
    errno = 0;
    ip_protocol = (uint8_t)strtoul(val_key, NULL, 0);
    if (errno != 0)
    {
        strncpy(message, "Error: ip protocol not in presenttion format\n", message_len);
        return false;
    }
    new_filter->ip_protocol = ip_protocol;
    new_filter->flags.ip_protocol_flag = 1;
    return true;
}


/* Parse ether type from string val_key to field of struct new_filter. */
bool
parse_ether_type(const char *name_key, const char *val_key,
    struct filter *new_filter, char *message, size_t message_len)
{
    uint16_t ether_type;

    if (strcmp(name_key, "ether_type") != 0)
        return true;
    if (new_filter->flags.ether_type_flag)
    {
        strncpy(message, "Error: ether type is set already \n", message_len);
        return false;
    }
    errno = 0;
    ether_type = (uint16_t)strtoul(val_key, NULL, 0);
    if (errno != 0)
    {
        strncpy(message, "Error: ether type not in presenttion format\n", message_len);
        return false;
    }
    new_filter->ether_type = htons(ether_type);
    new_filter->flags.ether_type_flag = 1;

    return true;
}


/* Parse src tcp from string val_key to field of struct new_filter. */
bool
parse_src_tcp(const char *name_key, const char *val_key,
    struct filter *new_filter, char *message, size_t message_len)
{
    uint16_t src_tcp;

    if (strcmp(name_key, "src_tcp") != 0)
        return true;
    if (new_filter->flags.src_tcp_flag){
        strncpy(message, "Error: src tcp is set already \n", message_len);
        return false;
    }
    errno = 0;
    src_tcp = (uint16_t)strtoul(val_key, NULL, 0);
    if (errno != 0)
    {
        strncpy(message, "Error: src tcp not in presenttion format\n", message_len);
        return false;
    }
    new_filter->src_tcp = htons(src_tcp);
    new_filter->flags.src_tcp_flag = 1;
    return true;
}


/* Parse dst tcp from string val_key to field of struct new_filter. */
bool
parse_dst_tcp(const char *name_key, const char *val_key,
    struct filter *new_filter, char *message, size_t message_len)
{
    uint16_t dst_tcp;

    if (strcmp(name_key, "dst_tcp") != 0)
        return true;
    if (new_filter->flags.dst_tcp_flag){
        strncpy(message, "Error: dst tcp is set already \n", message_len);
        return false;
    }
    errno = 0;
    dst_tcp = (uint16_t)strtoul(val_key, NULL, 0);
    if (errno != 0)
    {
        strncpy(message, "Error: dst tcp not in presenttion format\n", message_len);
        return false;
    }
    new_filter->dst_tcp = htons(dst_tcp);
    new_filter->flags.dst_tcp_flag = 1;
    return true;
}


/* Parse src udp from string val_key to field of struct new_filter. */
bool
parse_src_udp(const char *name_key, const char *val_key,
    struct filter *new_filter, char *message, size_t message_len)
{
    uint16_t src_udp;

    if (strcmp(name_key, "src_udp") != 0)
        return true;
    if (new_filter->flags.src_udp_flag)
    {
        strncpy(message, "Error: src udp is set already \n", message_len);
        return false;
    }
    errno = 0;
    src_udp = (uint16_t)strtoul(val_key, NULL, 0);
    if (errno != 0)
    {
        strncpy(message, "Error: src udp not in presenttion format\n", message_len);
        return false;
    }
    new_filter->src_udp = htons(src_udp);
    new_filter->flags.src_udp_flag = 1;
    return true;
}

/* Parsedst udp from string val_key to field of struct new_filter. */
bool
parse_dst_udp(const char *name_key, const char *val_key,
    struct filter *new_filter, char *message, size_t message_len)
{
    uint16_t dst_udp;

    if (strcmp(name_key, "dst_udp") != 0)
        return true;
    if (new_filter->flags.dst_udp_flag){
        strncpy(message, "Error: dst udp is set already \n", message_len);
        return false;
    }
    errno = 0;
    dst_udp = (uint16_t)strtoul(val_key, NULL, 0);
    if (errno != 0)
    {
        strncpy(message, "Error: dst udp not in presenttion format\n", message_len);
        return false;
    }
    new_filter->dst_udp = htons(dst_udp);
    new_filter->flags.dst_udp_flag = 1;
    return true;
}


/* Parse vlan id from string val_key to field of struct new_filter. */
bool
parse_vlan_id(const char *name_key, const char *val_key,
    struct filter *new_filter, char *message, size_t message_len)
{
    uint16_t vlan_id;

    if (strcmp(name_key, "vlan_id") != 0)
        return true;
    if (new_filter->flags.vlan_id_flag){
        strncpy(message, "Error: vlan flag is set already \n", message_len);
        return false;
    }
    errno = 0;
    vlan_id = (uint16_t)strtoul(val_key, NULL, 0);
    if (errno != 0)
    {
        strncpy(message, "Error: vlan id not in presenttion format\n", message_len);
        return false;
    }
    new_filter->vlan_id = vlan_id;
    new_filter->flags.vlan_id_flag = 1;
    return true;
}


/* Parse interface from string val_key to field of struct new_filter. */
bool
parse_interface(const char *name_key, const char *val_key,
    struct filter *new_filter, char *message, size_t message_len)
{
    int interface;

    if (strcmp(name_key, "interface") != 0)
        return true;
    if (new_filter->flags.interface_flag)
    {
        strncpy(message, "Error: interface is set already \n", message_len);
        return false;
    }
    errno = 0;
    interface = if_nametoindex(val_key);
    if (errno != 0)
    {
        strncpy(message, "Error: interface not in presenttion format\n", message_len);
        return false;
    }
    new_filter->interface = interface;
    new_filter->flags.interface_flag = 1;
    return true;
}