/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2022 OKTET Labs Ltd. All rights reserved. */
/** @file
 * @brief Linked list for filters
 *
 * There are: create, add to end, delete at position.
 */

#include "linked_list.h"
#include <stddef.h>

struct ts_node{
    struct filter data;
    struct ts_node *next;
};

static struct ts_node*
get_node_container(struct filter *node) {
    _Static_assert(offsetof(struct ts_node, data) == 0);
    return (struct ts_node*)node;
}

static void
ts_delete_first_node(struct filter **head)
{
    struct ts_node *tmp_node = get_node_container(*head);

    if (*head == NULL){
        printf("List is empty\n");
        return;
    }
    *head = &tmp_node->next->data;
    free(tmp_node);
}

struct ts_node*
create_node(struct filter const *new_filter)
{
    struct ts_node *new_node = malloc(sizeof(struct ts_node));
    if (!new_node) {
        //FIXME: abort
        return NULL;
    }
    new_node->data = *new_filter;
    new_node->next = NULL;
    return new_node;
}


struct filter* ts_get_data_next(struct filter *filter) {
    return &get_node_container(filter)->next->data;
}


void
ts_add_end_node(struct filter **head, struct filter const *new_filter)
{
    struct ts_node *cur_node = get_node_container(*head);
    struct ts_node *new_node = create_node(new_filter);

    if (*head == NULL)
    {
        *head = &new_node->data;
        return;
    }

    while(cur_node->next)
    {
        cur_node = cur_node->next;
    }

    cur_node->next = new_node;
}


void
ts_delete_position_node(struct filter **head, size_t position)
{
    struct ts_node *cur_node = get_node_container(*head); /* for cycle */
    struct ts_node *tmp_node; /* deleting node */

    if (cur_node == NULL)
    {
        // FIXME del printf
        printf("List is empty\n");
        return;
    }
    if (position == 0) {
        ts_delete_first_node(head);
        return;
    }


    for(size_t i = 0; cur_node && i < position - 1; i++)
    {
        cur_node = cur_node->next;
    }
    if (cur_node == NULL || cur_node->next == NULL) {
        printf("Position out of range\n");
        return;
    }
    tmp_node = cur_node->next;
    cur_node->next = cur_node->next->next;
    free(tmp_node);
}

