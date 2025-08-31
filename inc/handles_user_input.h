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
#include "linked_list.h"
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
extern void ts_send_statistics(struct ts_node **filter_list,
    size_t filters_len, int *sock_client);


/**
 * Splits the string into tokens and every token compare with keys.
 * Every key set in filers massive and set the flag indicating
 * what key is set. If key already is set, function returns empty filter.
 * If some key is invalid or other problems, function returns empty filter.
 * Send to sock_client message about result.
 *
 * @param buff                    string contain full ethernet packet
 * @param filter_list[out][in]    linked list of filters, that will be modified
 * @param filters_len[out][in]    filters len, that will be modified
 * @param sock_client              socket client where we send message
 *
 * @return                        true if success, false if fail
 *
 */
extern bool ts_add_filter(char *buff, struct ts_node **filter_list,  size_t *filters_len,
    int *sock_client);

/**
 * Delete filter by a number. Number of filter is taken from buffer.
 * Send to sock_client message about result.
 *
 * @param buff                    string contain message with command and argument
 * @param filters[out][in]        array of filters, that will be modified
 * @param filters_len[out][in]    filters len, that will be modified
 * @param sock_client              socket client where we send message
 *
 * @return bool                   true if success and false if fail
 *
 */
extern bool ts_delete_filter(char const *buff, struct ts_node **filter_list,  size_t *filters_len,
    int *sock_client);

#endif