/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2022 OKTET Labs Ltd. All rights reserved. */
/** @file
 * @brief User command processing utilities.
 *
 * Functions called depending on user input commands.
 */

#ifndef HANDLES_USER_INPUT_H
#define HANDLES_USER_INPUT_H

#include "filter.h"
#include <stdbool.h>
#include <stddef.h>


/**
 * Send message about all statistics.
 *
 * @param filters                  all setted filters
 * @param filters_len              count of setted filters
 * @param sock_client              socket client where we send message
 *
 */
extern void
send_statistics(struct filter const *filters,
    size_t filters_len, int *sock_client);


/**
 * Splits the string into tokens and every token compare with keys.
 * Every key set in filers massive and set the flag indicating
 * what key is set. If key already is set, next key will be ignored.
 * If some key is invalid or other problems, function returns empty filter.
 *
 * @param buff                    string contain full ethernet packet
 * @param filters[out][in]        array of filters, that will be modified
 * @param filters_len[out][in]    filters len, that will be modified
 * @param message[out]            message about the result of work
 * @param message_sz[in]          message size that have been set
 *
 * @todo                          add vlan_id, ipv6, interface
 *
 * @return                        true if success, false if fail
 *
 */
extern bool
add_filter(char *buff, struct filter *filters,  size_t *filters_len,
    char *message, size_t message_sz);

/**
 * Delete filter by a number. Number of filter is taken from buffer.
 *
 * @param buff                    string contain message with command and argument
 * @param filters[out][in]        array of filters, that will be modified
 * @param filters_len[out][in]    filters len, that will be modified
 * @param message_send[out]       message about the result of work
 *
 * @return bool                   true if success and false if fail
 *
 */
extern bool
delete_filter(char const *buff, struct filter *filters,  size_t *filters_len,
    char* message_send, size_t message_len);

#endif