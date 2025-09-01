/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2022 OKTET Labs Ltd. All rights reserved. */
/** @file
 * @brief Linked list for filters
 *
 * There are: create, add to end, delete at position.
 */

#include "linked_list.h"
#include <stddef.h>

/* Node for linked list. */
struct ts_node{
    struct filter data;
    struct ts_node *next;
};

/**
 * Get note container from structure filter.
 *
 * @param new_filter               filter of new node
 *
 * @return                         pointer to node
 *
 */
static struct ts_node*
get_node_container(struct filter *node) {
    /* Checking offset to be sure it is ok. */
    _Static_assert(offsetof(struct ts_node, data) == 0);
    return (struct ts_node*)node;
}

/**
 * Delete first node.
 *
 * @param head                     pointer to start of list
 *
 */
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

/**
 * Create a new node.
 *
 * @param new_filter               filter of new node
 *
 * @return                         pointer to a new node
 *
 */
static struct ts_node*
create_node(struct filter const *new_filter)
{
    struct ts_node *new_node = malloc(sizeof(struct ts_node));

    if (!new_node) {
        abort();
    }
    new_node->data = *new_filter;
    new_node->next = NULL;
    return new_node;
}

/* Return the next node of list. Using in cycles. */
struct filter* ts_get_data_next(struct filter *filter) {
    return &get_node_container(filter)->next->data;
}

/* Add new node to the end of list. */
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

    while (cur_node->next)
    {
        cur_node = cur_node->next;
    }

    cur_node->next = new_node;
}

/* Delete node by position of list. */
bool
ts_delete_position_node(struct filter **head, size_t position)
{
    struct ts_node *cur_node = get_node_container(*head); /* for cycle */
    struct ts_node *tmp_node; /* deleting node */

    if (cur_node == NULL)
        return false;

    if (position == 0) {
        ts_delete_first_node(head);
        return true;
    }

    for (size_t i = 0; cur_node && i < position - 1; i++)
    {
        cur_node = cur_node->next;
    }
    if (cur_node == NULL || cur_node->next == NULL) {
        printf("Position out of range\n");
        return false;
    }
    tmp_node = cur_node->next;
    cur_node->next = cur_node->next->next;
    free(tmp_node);
    return true;
}

/* Free memory occupied by linked list. */
void
free_list(struct filter **head)
{
    while (*head != NULL)
    {
        ts_delete_first_node(head);
    }
}
