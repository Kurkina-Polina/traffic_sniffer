/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2022 OKTET Labs Ltd. All rights reserved. */
/** @file
 * @brief User command processing utilities.
 *
 * Functions called depending on user input commands.
 */

#include "handles_user_input.h"
#include "filter.h"
#include "definitions.h"
#include "parsers.h"
#include "handles_sockets.h"
#include <stdlib.h>
#include <string.h>



/* Send message about all statistics. */
void
send_statistics(struct filter const *filters,
    size_t filters_len, int *sock_client)
{
    static char message_send[BUFFER_SIZE]; /* will be send to clint as result */

    if (filters_len <= 0)
    {
        snprintf(message_send, sizeof(message_send), "No filters yet\n");
        do_send(sock_client, message_send, strlen(message_send));
        return;
    }

    for (size_t i = 0; i < filters_len; i++)
    {
        snprintf(message_send, sizeof(message_send),
                "Filter number %zu: packets=%ld, total_size=%ld bytes\n",
                i + 1,
                filters[i].count_packets,
                filters[i].size);
        do_send(sock_client, message_send, strlen(message_send));
    }
}

/* Splits the string into tokens and every token compare with keys. */
bool
add_filter(char *buff, struct filter *filters,
    size_t *filters_len, char *message, size_t message_sz)
{
    static filter_param_setter* const array_parsers[] = {
        parse_dst_mac, parse_src_mac, parse_dst_ipv4, parse_src_ipv4, parse_ip_protocol,
        parse_ether_type, parse_src_tcp, parse_dst_tcp, parse_src_udp, parse_dst_udp,
        parse_interface, parse_dst_ipv6, parse_src_ipv6, parse_vlan_id,
    };
    struct filter new_filter = {0}; /* structure for new filter */
    static struct filter const empty_filter = {0}; /* structure for check if new_filter is empty */
    char *name_key; /* name of key */
    char *val_key; /* value of key */

    if (*filters_len >= MAX_FILTERS)
    {
        strncpy(message, "Error: limit of filters reached\n", message_sz);
        return false;
    }

    buff[strcspn(buff, "\r\n")] = '\0';
    DPRINTF("buffer |%s|\n", buff);

    name_key = strtok(buff + sizeof(CMD_ADD) - 1, " ");
    if (!name_key)
    {
        strncpy(message, "Error: No filter parameters\n", message_sz);
        return false;
    }

    while (name_key != NULL)
    {
        val_key = strtok(NULL, " ");
        if (!val_key) {
            strncpy(message, "Error: No filter\n", message_sz);
            return false;
        }
        DPRINTF("name_key |%s| val_key |%s| \n", name_key, val_key);
        for (size_t i = 0; i < ARRAY_SIZE(array_parsers); i++)
        {
            if(!array_parsers[i](name_key, val_key, &new_filter, message, message_sz))
                return false;
        }
        name_key = strtok(NULL, " ");
    }
    /* If new filter correctly added and it is not empty. */
    if (memcmp(&new_filter, &empty_filter, sizeof(new_filter)) != 0) {
        strncpy(message, "success\n", message_sz);
        filters[*filters_len] = new_filter;
        *filters_len += 1;
        return true;
    }
    strncpy(message, "unknown key\n", message_sz);
    return false;
}

/* Delete filter by a number. Number of filter is taken from buffer. */
bool
delete_filter(char const *buff, struct filter *filters,
              size_t *filters_len, char* message_send, size_t message_len)
{
    /* Find number of filter in buffer. */
    char const *num_filter = buff + sizeof(CMD_DEL) - 1;
    int int_num_filter; /* int number of filter */

    if (!num_filter)
    {
        strncpy(message_send, "Error: No number of filter \n", message_len);
        return false;
    }

    /* Convert it to int. */
    int_num_filter = atoi(num_filter) - 1;
    if (int_num_filter < 0 || (size_t)int_num_filter >= *filters_len)
    {
        DPRINTF("len %ld number %d \n", *filters_len, int_num_filter);
        strncpy(message_send, "Error: Invalid number of filter \n", message_len);
        return false;
    }

    /* Move all following at that place. */
    memmove(&filters[int_num_filter], &filters[int_num_filter + 1], (*filters_len - int_num_filter - 1) * sizeof(struct filter));
    *filters_len -= 1;
    strncpy(message_send, "Successfully delete \n", message_len);
    return true;
}