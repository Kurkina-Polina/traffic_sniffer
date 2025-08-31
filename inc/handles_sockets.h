/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2022 OKTET Labs Ltd. All rights reserved. */
/** @file
 * @brief Socket management and packet filtering.
 *
 * Socket lifecycle: creation, polling, cleanup.
 * Handles for polling.
 * Applying filters to incoming packets.
 */

#ifndef HANDLES_SOCKETS_H
#define HANDLES_SOCKETS_H

#include "filter.h"
#include <stdbool.h>
#include <poll.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>


/**
 * Sends data to the file descriptor.
 * Handles partial sends (when data is split across multiple packets).
 * Guarantees full data transmission (retries until all bytes are sent).
 *
 * @param fd                   file descriptor that receive info
 * @param data                 data to send
 * @param sz                   size of data
 *
 * @return                     0 if success errno if faild
 *
 */
extern int ts_do_send(int *fd, char const *const data, size_t sz);


/**
 * Check if the packet is suit for any filters.
 * Parse packet and then compare for each filter.
 * Print packet data for control.
 *
 * @param buffer              full buffer, received from client
 * @param bufflen             size of buffer
 * @param filters             all setted filters
 * @param filters_len         count of setted filters
 *
 * @sa                        check_src_mac check_src_ipv4 check_dst_mac
 *                            check_dst_ipv4 check_ip_protocol
 *                            check_ether_type check_src_tcp check_src_udp
 *                            check_dst_tcp check_dst_udp check_vlan_id
 *                            check_interface check_src_ipv6 check_dst_ipv6
 */
extern void ts_data_process(char const *buffer, size_t bufflen,
    struct filter* filters, size_t filters_len, struct sockaddr_ll sniffaddr);


/**
 * Receive a packet on sock_client and process a data.
 * Calls a function by any command in the packet.
 * Send message to sock_client about the results.
 *
 * @param sock_client          opened socket that receive info
 * @param filters [out]        all set filters
 * @param filters_len [out]    count of filters set
 *
 */
extern void ts_handle_client_event(int *const sock_client,
    struct filter *filters,  size_t *filters_len);


/**
 * Handle the listen socket if there is signal to connect.
 * Establishes a connection with client.
 * Reject if already connected (send error and close).
 *
 * @param sock_listen          listening socket
 * @param sock_client          socket of client
 *
 * @return                     errno
 */
extern int ts_handle_listen(int* sock_listen, int* sock_client);


/**
 * Handle the sniffer socket if there is signal to new packet.
 * Receive a packet from socket and
 * pass the packet to data_process for unpacking.
 *
 * @param sock_sniffer         sniffering socket
 * @param filters              array of filters
 * @param filters_len          count of filters
 *
 * @return                     errno
 */
extern int ts_handle_sniffer(int *sock_sniffer, struct filter *filters,  size_t filters_len);


/**
 * Cycle for poll.
 *
 * @param fds                  opened socket that receive info
 * @param count_sockets        count of all sockets in poll
 *
 */
extern void ts_poll_loop(struct pollfd *fds, size_t const count_sockets);


/**
 * Set up sockets, addresses and structure for poll.
 * fds is array of 3 sockets: sniffing, listening and client.
 *
 * @param fds                  opened socket that receive info
 * @param port_server          port on which server works
 * @param ip_server            ip address on which server works
 *
 * @return                     0 if success and -1 if fail
 *
 */
extern int ts_setup_sockets(struct pollfd *fds,
    uint16_t port_server, uint32_t ip_server);

#endif