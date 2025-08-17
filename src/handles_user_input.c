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
    }
    int message_len = 0;
    for (size_t i = 0; i < filters_len; i++)
    {
        message_len += snprintf(message+message_len, message_sz,
                "Filter number %zu: packets=%ld, total_size=%ld bytes\n",
                i + 1,
                filters[i].count_packets,
                filters[i].size);
    }
}

struct filter
add_filter(char *buff, char *message, size_t message_sz)
{
    bool (*array_parsers[])(const char *name_key, const char *val_key, struct filter *new_filter, char *message) = {
        parse_dst_mac, parse_src_mac, parse_dst_ipv4, parse_src_ipv4, parse_ip_protocol,
        parse_ether_type, parse_src_tcp, parse_dst_tcp, parse_src_udp, parse_dst_udp, parse_vlan_id,
        parse_interface, parse_dst_ipv6, parse_src_ipv6,
    };
    struct filter new_filter = {0};
    static struct filter const empty_filter = {0};
    buff[strcspn(buff, "\r\n")] = '\0';
    DPRINTF("buffer |%s|\n", buff);

    char *name_key = strtok(buff + sizeof(CMD_ADD) - 1, " ");
    if (!name_key)
    {
        strcpy(message, "Error: No filter parameters\n");
        return new_filter;
    }

    while (name_key != NULL)
    {
        char *val_key = strtok(NULL, " ");
        if (!val_key) {
            strcpy(message, "Error: No filter\n");
            return empty_filter;
        }
        DPRINTF("name_key |%s| val_key |%s| \n", name_key, val_key);
        for (size_t i = 0; i < KEYS_COUNT; i++)
        {
            if(!array_parsers[i](name_key, val_key, &new_filter, message))
                return empty_filter;
        }
        name_key = strtok(NULL, " ");
    }
    strcpy(message, "success\n");
    return new_filter;
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