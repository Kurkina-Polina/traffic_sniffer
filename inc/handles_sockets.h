#ifndef HANDLES_SOCKETS_H
#define HANDLES_SOCKETS_H

#include "filter.h"
#include <stdbool.h>
#include <poll.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>


/**
 * Send data to the file descriptor.
 *
 * @param fd                   file descriptor that receive info
 * @param data                 data to send
 * @param sz                   size of data
 *
 * @return                     0 if success errno if faild
 *
 */
int
do_send(int fd, char const *const data, size_t sz);


/**
 * Handler for interrupt by SIGINT.
 */
static void
sig_handler(int unused);


/**
 * Compare the packet with all fields in the filter.
 *
 * @param packet_data          data of the packet
 * @param cur_filter           current filter that cheking
 *
 * @return                     true if suit, false if not suit
 *
 */
static bool check_filter_match(const struct filter packet_data, const struct filter cur_filter);

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
void
data_process(char const *buffer, size_t bufflen,
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
void
handle_client_event(int *const sock_client,
    struct filter *filters,  size_t *filters_len);


/**
 * Handle the listen socket if there is signal to connect.
 * Establishes a connection with client.
 * Reject if already connected (send error and close).
 *
 * @param sock_listen          listening socket
 * @param sock_client          socket of client
 *
 */
void
handle_listen(int* sock_listen, int* sock_client);


/**
 * Handle the sniffer socket if there is signal to new packet.
 * Receive a packet from socket and
 * pass the packet to data_process for unpacking.
 *
 * @param sock_sniffer         sniffering socket
 * @param filters              array of filters
 * @param filters_len          count of filters
 *
 */
void
handle_sniffer(int sock_sniffer, struct filter *filters,  size_t filters_len);


/**
 * Cycle for poll.
 *
 * @param fds                  opened socket that receive info
 * @param count_sockets        count of all sockets in poll
 *
 */
void
poll_loop(struct pollfd *fds, size_t const count_sockets);


/**
 * Set up sockets, addresses and structure for poll.
 *
 * @param fds                  opened socket that receive info
 * @param port_server          port on which server works
 * @param ip_server            ip address on which server works
 *
 * @return                     0 if success and -1 if fail
 *
 */
int
setup_sockets(struct pollfd *fds,
    uint16_t port_server, uint32_t ip_server);

#endif