/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2022 OKTET Labs Ltd. All rights reserved. */
/** @file
 * @brief Program usage information.
 *
 * Make message about program usage information.
 */

char const*
ts_get_help_message()
{
    return "\n------------------------------------------------------\n"
    "Usage: "
    "add <key> <value>  <key> <value> - add filter\n"
    "print - print statics on filters\n"
    "exit - to close connection\n"
    "del <number of filter> - delete filter by number\n"
    "On one filter you can use only one same keys:\n"
    "\n"
    "possible keys:\n"
    "\n"
    "src_mac\n"
    "dst_mac\n"
    "ether_type\n "
    "vlan_id\n"
    "ip_protocol\n"
    "dst_ipv4\n"
    "src_ipv4\n"
    "dst_ipv6\n"
    "src_ipv6\n"
    "src_tcp\n"
    "dst_tcp\n"
    "src_udp\n"
    "dst_udp\n"
    "\n"
    "------------------------------------------------------\n";
}