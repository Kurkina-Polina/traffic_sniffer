/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2022 OKTET Labs Ltd. All rights reserved. */
/** @file
 * @brief Linked list for filters
 *
 * There are: create, add to end, delete at position.
 */

#ifndef LINKED_LIST_H
#define LINKED_LIST_H
#include "filter.h"
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>

extern void ts_add_end_node(struct filter **head, const struct filter *new_filter);

extern void ts_delete_position_node(struct filter **head, size_t position);

extern  struct filter* ts_get_data_next(struct filter* filter);

#endif