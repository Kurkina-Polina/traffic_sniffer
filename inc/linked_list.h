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

struct ts_node{
    struct filter data;
    struct ts_node *next;
};

extern void ts_add_end_node(struct ts_node **head, struct filter new_filter);

extern void ts_delete_first_node(struct ts_node **head);

extern void ts_delete_end_node(struct ts_node **head);

extern void ts_delete_position_node(struct ts_node **head, int position);

extern struct ts_node* ts_get_node_position(struct ts_node **head, size_t position);

static struct filter* ts_get_data_next(struct ts_node **node) {
    *node = (*node)->next;
    if (*node == NULL)
        return NULL;
    return &(*node)->data;
}

#endif