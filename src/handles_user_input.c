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
#include "parsers_str.h"
#include "handles_sockets.h"
#include <stdlib.h>
#include <string.h>



/* Send message about all statistics. */
//FIXME: struct ts_node **filter_list cant be const??
void
ts_send_statistics(struct filter ** const filter_list,
    size_t filters_len, int *sock_client)
{
    static char message_send[BUFFER_SIZE] = {}; /* will be send to clint as result */
    struct filter *cur_filter = *filter_list; /* tmp filter for cycle */
    size_t number_filter = 0;

    if (filters_len <= 0)
    {
        snprintf(message_send, sizeof(message_send), "No filters yet\n");
        ts_do_send(sock_client, message_send, strlen(message_send));
        return;
    }

    for(; cur_filter != NULL;  cur_filter = ts_get_data_next(cur_filter))
    {
        snprintf(message_send, sizeof(message_send),
                "Filter number %zu: packets = %ld, total_size = %ld bytes\n",
                number_filter + 1,
                cur_filter->count_packets,
                cur_filter->size);

        ts_do_send(sock_client, message_send, strlen(message_send));
        number_filter++;
    }
}

/* Splits the string into tokens and every token compare with keys. */
bool
ts_add_filter(char *buff, struct filter **filter_list,
    size_t *filters_len, int *sock_client)
{
    static ts_filter_param_setter* const array_parsers[] = {
        ts_parse_str_dst_mac, ts_parse_str_src_mac, ts_parse_str_dst_ipv4, ts_parse_str_src_ipv4, ts_parse_str_ip_protocol,
        ts_parse_str_ether_type, ts_parse_str_src_tcp, ts_parse_str_dst_tcp, ts_parse_str_src_udp, ts_parse_str_dst_udp,
        ts_parse_str_interface, ts_parse_str_dst_ipv6, ts_parse_str_src_ipv6, ts_parse_str_vlan_id,
    };
    struct filter new_filter = {0}; /* structure for new filter */
    static struct filter const empty_filter = {0}; /* structure for check if new_filter is empty */
    char *name_key; /* name of key */
    char *val_key; /* value of key */
    char message_send[BUFFER_SIZE] = {}; /* will be send to clint as result */


    buff[strcspn(buff, "\r\n")] = '\0';
    DPRINTF("buffer |%s|\n", buff);

    name_key = strtok(buff + sizeof(CMD_ADD) - 1, " ");
    if (!name_key)
    {
        snprintf(message_send, sizeof(message_send),  "Error: No filter parameters\n");
        ts_do_send(sock_client, message_send, strlen(message_send));
        return false;
    }

    while (name_key != NULL)
    {
        val_key = strtok(NULL, " ");
        if (!val_key) {
            snprintf(message_send, sizeof(message_send),  "Error: No filter\n");
            ts_do_send(sock_client, message_send, strlen(message_send));
            return false;
        }
        DPRINTF("name_key |%s| val_key |%s| \n", name_key, val_key);
        for (size_t i = 0; i < ARRAY_SIZE(array_parsers); i++)
        {
            if(!array_parsers[i](name_key, val_key, &new_filter, message_send, sizeof(message_send)))
            {
                ts_do_send(sock_client, message_send, strlen(message_send));
                return false;
            }
        }
        name_key = strtok(NULL, " ");
    }
    /* If new filter correctly added and it is not empty. */
    if (memcmp(&new_filter, &empty_filter, sizeof(new_filter)) != 0) {
        snprintf(message_send, sizeof(message_send),  "Success\n");
        ts_do_send(sock_client, message_send, strlen(message_send));
        ts_add_end_node(filter_list, &new_filter);
        *filters_len += 1;
        return true;
    }
    snprintf(message_send, sizeof(message_send),  "Uknown key\n");
    ts_do_send(sock_client, message_send, strlen(message_send));
    return false;
}

/* Delete filter by a number. Number of filter is taken from buffer. */
bool
ts_delete_filter(char const *buff, struct filter **filter_list,
              size_t *filters_len, int *sock_client)
{
    /* Find number of filter in buffer. */
    char const *num_filter = buff + sizeof(CMD_DEL) - 1;
    int int_num_filter; /* int number of filter */
    char message_send[BUFFER_SIZE] = {}; /* will be send to clint as result */

    if (!num_filter)
    {
        snprintf(message_send, sizeof(message_send),  "Error: No number of filter \n");
        ts_do_send(sock_client, message_send, strlen(message_send));
        return false;
    }

    /* Convert it to int. */
    int_num_filter = atoi(num_filter) - 1;
    if (int_num_filter < 0 || (size_t)int_num_filter >= *filters_len)
    {
        DPRINTF("len %ld number %d \n", *filters_len, int_num_filter);
        snprintf(message_send, sizeof(message_send),  "Error: Invalid number of filter \n");
        ts_do_send(sock_client, message_send, strlen(message_send));
        return false;
    }

    /* Move all following at that place. */
    ts_delete_position_node(filter_list, int_num_filter);
    *filters_len -= 1;
    snprintf(message_send, sizeof(message_send),  "Successfully delete \n");
    ts_do_send(sock_client, message_send, strlen(message_send));
    return true;
}