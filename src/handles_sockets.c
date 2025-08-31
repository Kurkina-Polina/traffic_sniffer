/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2022 OKTET Labs Ltd. All rights reserved. */
/** @file
 * @brief Socket operations and packet filtering.
 *
 * Socket lifecycle: creation, polling, cleanup.
 * Handles for polling.
 * Applying filters to incoming packets.
 */
#include "handles_sockets.h"
#include "checkers.h"
#include "handles_user_input.h"
#include "parsers_pkt.h"
#include "printers.h"
#include "get_help.h"
#include <errno.h>
#include <stdbool.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

/* Flag for end program. */
static volatile bool keep_running = 1;

/* Sends data to the file descriptor even if it is split. */
int
ts_do_send(int *fd, char const *const data, size_t sz)
{
    size_t written_bytes = 0;
    ssize_t rc; /* returned code by send */

    for (; written_bytes != sz;) {
        rc = send(*fd, data + written_bytes,
            sz - written_bytes, MSG_DONTWAIT);
        if (rc <= 0)  {
            rc = rc ? errno : ENOTCONN;
            printf("Failed to send data: %s\n", strerror(rc));
            if (close(*fd) == -1)
                perror("Error in close connection: ");
            *fd = INVALID_SOCKET;
            return -rc;
        }
        written_bytes += rc;
    }
    return 0;
}


/**
 * Handler for interrupt by SIGINT.
 */
static void
sig_handler(int unused)
{
    (void)unused;
    keep_running = 0;
}


/**
 * Compare the packet with all fields in the filter.
 *
 * @param packet_data          data of the packet
 * @param cur_filter           current filter that cheking
 *
 * @return                     true if suit, false if not suit
 *
 */
static bool check_filter_match(const struct filter packet_data, const struct filter* const cur_filter)
{
    static filter_param_compare* const array_checks[]= {
        ts_check_dst_mac, ts_check_src_mac, ts_check_dst_ipv4, ts_check_src_ipv4, ts_check_ip_protocol,
        ts_check_ether_type, ts_check_src_tcp, ts_check_dst_tcp, ts_check_src_udp, ts_check_dst_udp, ts_check_vlan_id,
        ts_check_interface, ts_check_dst_ipv6, ts_check_src_ipv6,
    };

    for (size_t j = 0; j < ARRAY_SIZE(array_checks); j++){
        if (!array_checks[j](&packet_data, cur_filter))
            return false;
    }
    return true;
}


/* Parse packet and then compare for each filter.*/
void
ts_data_process(char const *buffer, size_t bufflen,
    struct filter **filter_list, struct sockaddr_ll sniffaddr)
{
    /* Unpacking packet to filter structure for simple comparing. */
    struct filter packet_data = {0};
    size_t num_filter = 0; /* number of filter */
    struct filter* node = *filter_list;

    /* If no filters, do not parse packet*/
    if (*filter_list == NULL)
        return;
    ts_parser_pkt_ether(buffer, bufflen, &packet_data, sniffaddr);

    /* Compare with each filter. */
    for(; node != NULL;  node = ts_get_data_next(node))
    {
        if (check_filter_match(packet_data, node))
        {
            node->count_packets += 1;
            node->size += bufflen;
            DPRINTF("SUITABLE +1 packet on filter %zu: %ld\n\n",
                num_filter, node->count_packets);
        }
        else
            DPRINTF("NOT SUITABLE on filter %ld\n\n", num_filter);
        num_filter++;
    }

    ts_print_packet(buffer, bufflen, sniffaddr);
}


/* Receive a packet on sock_client and calls a function by any command. */
void
ts_handle_client_event(int *const sock_client,
    struct filter **filter_list,  size_t *filters_len)
{
    char rx_buffer[BUFFER_SIZE] = {}; /* for client input */
    //FIXME: remove this message_send and just send data
    static char message_send[BUFFER_SIZE]; /* will be sent to client as result */
    ssize_t const rc = read(*sock_client, rx_buffer, sizeof(rx_buffer));

    if (rc <= 0)
    {
        close(*sock_client);
        if (rc == 0)
            printf("Client closed the connection during read\n");
        *sock_client = INVALID_SOCKET;
        return;
    }

    DPRINTF("From client:\n%s\n", rx_buffer);
    memset(message_send, '\0', BUFFER_SIZE);

    /* Process command from client. */
    if (strncmp(CMD_ADD, rx_buffer, sizeof(CMD_ADD) - 1) == 0)
        ts_add_filter(rx_buffer, filter_list, filters_len,
            sock_client);

    else if (strncmp(CMD_DEL, rx_buffer, sizeof(CMD_DEL) - 1) == 0)
        ts_delete_filter(rx_buffer, filter_list, filters_len, sock_client);

    else if (strncmp(CMD_PRINT, rx_buffer, sizeof(CMD_PRINT) - 1) == 0)
        ts_send_statistics(filter_list, *filters_len, sock_client);

    else if (strncmp(CMD_EXIT, rx_buffer, sizeof(CMD_EXIT) - 1) == 0)
    {
        strcpy(message_send, "exiting\n");
        ts_do_send(sock_client, message_send, strlen(message_send));
        if (close(*sock_client) == -1)
            perror("Error in close connection: ");
        *sock_client = INVALID_SOCKET;
        return;
    }
    else /* unknown command */
        strcpy(message_send, ts_get_help_message());

    ts_do_send(sock_client, message_send, strlen(message_send));
}

/* Establishes a connection with client. Reject if already connected. */
int
ts_handle_listen(int* sock_listen, int* sock_client)
{
    /* Make new connection with client. */
    socklen_t sock_client_len = sizeof(struct sockaddr_in);
    struct sockaddr_in clientaddr;
    char const already_busy_message[] = "Failed to accept"
            " connection since there is already opened one\n";

    int fd = accept(*sock_listen, (struct sockaddr*)&clientaddr, &sock_client_len);
    if (fd == -1)
    {
        perror("Failed to accept connection");
        return -EBADF;
    }

    /* Reject if already connected. */
    if (*sock_client != INVALID_SOCKET)
    {
        printf("%s", already_busy_message);
        ts_do_send(&fd, already_busy_message, sizeof(already_busy_message));
        if (close(fd) == 0)
            perror("Error in close connection: ");
        return 0;
    }
    printf("Connection accepted\n");
    *sock_client = fd;
    return 0;
}

/* Receive a packet from socket and
pass the packet to data_process for unpacking. */
int
ts_handle_sniffer(int *sock_sniffer, struct filter **filter_list)
{
    static char buffer[BUFFER_SIZE]; /* buffer that will contain a full packet*/
    struct sockaddr_ll snifaddr = {0}; /* it will contain a vlan */
    socklen_t snifaddr_len = sizeof(snifaddr);
    ssize_t const receive_count = recvfrom(*sock_sniffer,
        buffer, sizeof(buffer), 0, (struct sockaddr*)&snifaddr, &snifaddr_len);

    if (receive_count < 0)
    {
        close(*sock_sniffer);
        *sock_sniffer = INVALID_SOCKET;
        perror("error in reading recvfrom function\n");
        return -EBADF;
    }
    ts_data_process(buffer, receive_count, filter_list, snifaddr);
    return 0;
}

void
ts_poll_loop(struct pollfd *fds, size_t const count_sockets)
{
    size_t filters_len = 0;
    struct filter *filter_list = NULL; /* linked list of filters */
    int count_poll; /* number of ready file descriptors returned by poll() */

    signal(SIGINT, sig_handler); /* Set up SIGINT handler for correct end*/

    while (keep_running)
    {
        count_poll = poll(fds,  count_sockets, TIMEOUT_MS);
        if (count_poll == -1)
        {
            perror("Error in poll :");
            break;
        }

        if (count_poll == 0)
            continue;

        if (fds[SNIFFER_INDEX].revents & POLL_IN)
        {
            if(ts_handle_sniffer(&fds[SNIFFER_INDEX].fd, &filter_list) != 0)
                goto on_fail;
        }

        if (fds[LISTEN_INDEX].revents & POLL_IN)
        {
            if (ts_handle_listen(&fds[LISTEN_INDEX].fd, &fds[CLIENT_INDEX].fd) != 0)
                goto on_fail;
        }

        if (fds[CLIENT_INDEX].revents & POLL_IN)
        {
            ts_handle_client_event(&fds[CLIENT_INDEX].fd, &filter_list, &filters_len);
        }

        if (fds[CLIENT_INDEX].revents & POLLHUP || fds[CLIENT_INDEX].revents & POLLERR)
        {
            printf("closing connection\n");
            if (!close(fds[CLIENT_INDEX].fd))
                perror("Error in close connection: ");
            fds[CLIENT_INDEX].fd = INVALID_SOCKET;
        }
    }
on_fail:
    if (fds[CLIENT_INDEX].fd != INVALID_SOCKET)
        close(fds[CLIENT_INDEX].fd);
    if (fds[SNIFFER_INDEX].fd != INVALID_SOCKET)
        close(fds[SNIFFER_INDEX].fd);
    if (fds[LISTEN_INDEX].fd != INVALID_SOCKET)
        close(fds[LISTEN_INDEX].fd);
    //FIXME: как очиащть список? отдельную функцию делать которая рекурсивно очищать будет?
}


int
ts_setup_sockets(struct pollfd *fds,
    uint16_t port_server, uint32_t ip_server)
{
    int sock_sniffer;
    int sock_listen;
    /* Server's listening socket address (IP+port for clients to connect). */
    struct sockaddr_in servaddr = {
        .sin_family = AF_INET,
        .sin_addr = { .s_addr = ip_server, },
        .sin_port = port_server,
    };

    if ((sock_sniffer = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("failed to create sniffer socket\n");
        return -errno;
    }
    if ((sock_listen = socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0)) < 0) {
        perror("failed to create listen socket\n");
        close(sock_sniffer);
        return -errno;
    }


    if (setsockopt(sock_listen, SOL_SOCKET, SO_REUSEADDR,
        &(int){1}, sizeof(int)) < 0)
    {
        perror("setsockopt(SO_REUSEADDR) failed");
        close(sock_sniffer);
        close(sock_listen);
        return -errno;
    }

    if ((bind(sock_listen, (struct sockaddr*)&servaddr, sizeof(servaddr))) != 0)
    {
        perror("socket bind failed...\n");
        close(sock_sniffer);
        close(sock_listen);
        return -errno;
    }

    if ((listen(sock_listen, 5)) != 0)
    {
        perror("Listen failed...\n");
        close(sock_sniffer);
        close(sock_listen);
        return -errno;
    }

    fds[SNIFFER_INDEX].fd = sock_sniffer;
    fds[SNIFFER_INDEX].events = POLL_IN;
    fds[LISTEN_INDEX].fd = sock_listen;
    fds[LISTEN_INDEX].events = POLL_IN;
    fds[CLIENT_INDEX].fd = INVALID_SOCKET; /* empty by default */
    fds[CLIENT_INDEX].events = POLL_IN;

    return 0;
}