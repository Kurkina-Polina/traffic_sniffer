#include "handles_user_input.h"

#include <stdlib.h>
#include <string.h>

#include "filter.h"
#include "definitions.h"
#include "parsers.h"
#include "handles_sockets.h"

void
get_statistics(struct filter const *filters,
    size_t filters_len, char *message, size_t message_sz)
{
    if(filters_len<=0)
    {
        snprintf(message, message_sz, "No filters yet\n");
        return;
    }
    int message_len = 0;
    for (size_t i = 0; i < filters_len; i++)
    {
        //FIXME: what do we do if buffer is overfilled?
        message_len += snprintf(message+message_len, message_sz,
                "Filter number %zu: packets=%ld, total_size=%ld bytes\n",
                i + 1,
                filters[i].count_packets,
                filters[i].size);
    }
}

bool
add_filter(char *buff, struct filter *filters,  size_t *filters_len, char *message, size_t message_sz)
{
    static bool (* const array_parsers[])(const char *name_key, const char *val_key, struct filter *new_filter, char *message) = {
        parse_dst_mac, parse_src_mac, parse_dst_ipv4, parse_src_ipv4, parse_ip_protocol,
        parse_ether_type, parse_src_tcp, parse_dst_tcp, parse_src_udp, parse_dst_udp, parse_vlan_id,
        parse_interface, parse_dst_ipv6, parse_src_ipv6,
    };
    struct filter new_filter = {0}; /* structure for new filter */
    static struct filter const empty_filter = {0}; /* structure for check if new_filter is empty */
    buff[strcspn(buff, "\r\n")] = '\0';
    DPRINTF("buffer |%s|\n", buff);

    char *name_key = strtok(buff + sizeof(CMD_ADD) - 1, " ");
    if (!name_key)
    {
        strncpy(message, "Error: No filter parameters\n", message_sz);
        return false;
    }

    while (name_key != NULL)
    {
        char *val_key = strtok(NULL, " ");
        if (!val_key) {
            strncpy(message, "Error: No filter\n", message_sz);
            return false;
        }
        DPRINTF("name_key |%s| val_key |%s| \n", name_key, val_key);
        for (size_t i = 0; i < ARRAY_SIZE(array_parsers); i++)
        {
            if(!array_parsers[i](name_key, val_key, &new_filter, message))
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

bool
delete_filter(char const *buff, struct filter *filters,  size_t *filters_len, char* message_send)
{
    char const *num_filter = buff + sizeof(CMD_DEL) - 1;
    if (!num_filter)
    {
        strcpy(message_send, "Error: No number of filter \n");
        return false;
    }
    //FIXME: add error checks
    int int_num_filter = atoi(num_filter)-1;
    if (int_num_filter < 0 || int_num_filter >= *filters_len)
    {
        DPRINTF("len %ld number %d \n", *filters_len, int_num_filter);
        strcpy(message_send, "Error: Invalid number of filter \n");
        return false;
    }
    memmove(&filters[int_num_filter], &filters[int_num_filter+1], (*filters_len - int_num_filter-1)*sizeof(struct filter));
    *filters_len -= 1;
    strcpy(message_send, "Successfuly delete \n");
    return true;
}