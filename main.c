/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2022 OKTET Labs Ltd. All rights reserved. */
/** @file
 * @brief Network traffic analyzer tool.
 *
 * Chip-specific primitive implementation.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "definitions.h"
#include "handles_sockets.h"


/**
 * Process arguments.
 *
 * @param argc
 * @param argv
 * @param ip_server[out]       pointer to write ip address of server
 * @param port_server[out]     pointer to write tcp port of server
 *
 */
void
command_line(int argc, char *argv[], struct in_addr *ip_server,
    uint16_t *port_server)
{
    for (int opt;(opt = getopt(argc, argv, "a:p:h:")) != -1;) {
        switch (opt)
        {
            case 'a':
                if (inet_pton(AF_INET, optarg, ip_server) <= 0)
                {
                    fprintf(stderr, "Invalid value for ip address\n");
                    exit(EXIT_FAILURE);
                }
                break;

            case 'p':
                *port_server = htons((uint16_t)strtoul(optarg, NULL, 0));
                break;
            case 'h':
            default:
                fprintf(stderr, "Usage: %s -a <IP> -p <PORT>\n", argv[0]);
                exit(opt == 'h' ? EXIT_SUCCESS : EXIT_FAILURE);
        }
    }
    if (ip_server->s_addr == 0) {
        fprintf(stderr, "Usage: %s -a <IP> -p <PORT>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    if (port_server == 0) {
        fprintf(stderr, "Usage: %s -a <IP> -p <PORT>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    printf("starting on %s and on port %u\n",
        inet_ntoa(*ip_server), ntohs(*port_server));
}


int
main(int argc, char *argv[])
{
    struct in_addr ip_server = {0};
    uint16_t port_server = 0;
    struct pollfd fds[3];

    command_line(argc, argv, &ip_server, &port_server);

    if (setup_sockets(fds, port_server, ip_server.s_addr) != 0)
        return EXIT_FAILURE;

    poll_loop(fds, ARRAY_SIZE(fds));
    return 0;
}
