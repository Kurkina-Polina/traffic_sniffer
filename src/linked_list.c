/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2022 OKTET Labs Ltd. All rights reserved. */
/** @file
 * @brief Linked list for filters
 *
 * There are: create, add to end, delete at position.
 */

#include "linked_list.h"

struct ts_node*
crate_node(struct filter new_filter)
{
    struct ts_node *new_node = (struct ts_node*)malloc(sizeof(struct ts_node));
    new_node->data = new_filter;
    new_node->next = NULL;
    return new_node;
}

void
ts_add_end_node(struct ts_node **head, struct filter new_filter)
{
    struct ts_node *cur_node = *head;
    struct ts_node *new_node = crate_node(new_filter);

    if (*head == NULL)
    {
        *head = new_node;
        return;
    }

    while(cur_node->next)
    {
        cur_node = cur_node->next;
    }

    cur_node->next = new_node;
}

void
ts_delete_first_node(struct ts_node **head)
{
    struct ts_node *tmp_node = *head;

    if (*head == NULL){
        printf("List is empty\n");
        return;
    }
    *head = tmp_node->next;
    free(*head);
}

void
ts_delete_end_node(struct ts_node **head)
{
    struct ts_node *cur_node = *head;

    if (*head == NULL){
        printf("List is empty\n");
        return;
    }
    if (cur_node->next == NULL)
    {
        free(cur_node);
        *head = NULL;
        return;
    }
    while (cur_node->next->next)
    {
        cur_node = cur_node->next;
    }
    free(cur_node->next);
    cur_node->next = NULL;

}

void
ts_delete_position_node(struct ts_node **head, int position)
{
    struct ts_node *cur_node; /* for cycle */
    struct ts_node *tmp_node; /* deleting node */

    if (*head == NULL){
        printf("List is empty\n");
        return;
    }
    if (position == 0)
    {
        ts_delete_first_node(head);
    }
    for(int i = 0; cur_node && i < position - 1; i++)
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

//FIXME: can be const
struct ts_node*
ts_get_node_position(struct ts_node **head, size_t position)
{
    struct ts_node *cur_node = *head;

    for (size_t i = 0; cur_node && i < position; i++)
    {
        cur_node = cur_node->next;
    }
    return cur_node;
}
