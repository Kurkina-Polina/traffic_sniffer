/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2022 OKTET Labs Ltd. All rights reserved. */
/** @file
 * @brief Packet dissection and displaying.
 *
 * Implements layered packet parsing architecture for terminal output.
 */

#ifndef PRINTERS_H
#define PRINTERS_H
#include "filter.h"
#include "definitions.h"
#include <linux/if_packet.h>


/**
 * Print MAC address.
 *
 * @param addr    MAC address in uint8_t
 */
extern  void ts_print_mac_addr(uint8_t const *addr);

/**
 * Print data of a packet like hexdump.
 *
 * @param data    pointer of start data
 * @param size    size of data
 */
extern  void ts_print_payload(char const *data, size_t size);
/**
 * Print tcp header of a packet.
 *
 * @param buffer    pointer of start payload
 * @param bufflen   size of buffer
 * @param iphdrlen  size of ip header in bytes
 *
 * @sa print_payload
 */
extern  void ts_tcp_header(char const *buffer, size_t bufflen);

/**
 * Print udp header of a packet.
 *
 * @param buffer    pointer of start header
 * @param bufflen   size of buffer
 * @param iphdrlen  size of ip header in bytes
 *
 * @sa print_payload
 */
extern void ts_udp_header(char const *buffer, size_t bufflen);

/**
 * Print ipv4 header of a packet.
 *
 * @param buffer    pointer of start header
 * @param buf_flen  size of buffer
 *
 * @sa tcp_header udp_header
 */
extern void ts_print_ipv4(char const *buffer, size_t buf_flen);

/**
 * Print ipv6 header of a packet.
 *
 * @param buffer    pointer of start header
 * @param buf_flen  size of buffer
 *
 * @sa tcp_header udp_header
 */
extern void ts_print_ipv6(char const *buffer, size_t buf_flen);

/**
 * Print vlan header of a packet.
 *
 * @param buffer    pointer of start header
 * @param buf_flen  size of buffer
 *
 * @sa print_ipv6 print_ipv4
 */
extern void ts_print_vlan(char const *buffer, size_t buf_flen);

/**
 * Print all headers of packet and data.
 *
 * @param buffer    pointer of start header
 * @param bufflen   size of buffer
 *
 * @sa ip_header
 */
extern void ts_print_packet(char const *buffer, size_t bufflen,  struct sockaddr_ll sniffaddr);

#endif