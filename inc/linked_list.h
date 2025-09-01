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
#include <stdbool.h>

/**
 * Add new node to the end of list.
 *
 * @param head                     head of list
 * @param new_filter               new filter
 *
 */
extern void ts_add_end_node(struct filter **head, const struct filter *new_filter);

/**
 * Delete node by position of list.
 *
 * @param head                     head of list
 * @param position                 position of deleting node
 *
 */
extern bool ts_delete_position_node(struct filter **head, size_t position);

/**
 * Return the next node of list. Using in cycles.
 *
 * @param filter                   previous node of list
 *
 * @return                         next node of list
 *
 */
extern struct filter* ts_get_data_next(struct filter* filter);

/**
 * Free memory occupied by linked list.
 *
 * @param filter                   previous node of list
 *
 * @return                         next node of list
 *
 */
extern void free_list(struct filter **head);

#endif