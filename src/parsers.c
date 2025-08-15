#include "parsers.h"
#include <arpa/inet.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <net/if.h>

/**
 * Parse MAC address from string to struct of ether header.
 *
 * @param str                  string contain mac address
 * @param mac[out]             parsed mac address
 *
 */
bool
parse_mac(const char *str, struct ether_addr *mac)
{
    return sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                 &mac->ether_addr_octet[0], &mac->ether_addr_octet[1],
                 &mac->ether_addr_octet[2], &mac->ether_addr_octet[3],
                 &mac->ether_addr_octet[4], &mac->ether_addr_octet[5]) == 6;
}

bool
parse_src_ipv4(const char *name_key, const char *val_key, struct filter *new_filter, char *message)
{
    if ((strcmp(name_key, "src_ipv4") == 0) && (new_filter->flags.src_ipv4_flag == 0))
        {
            int result = inet_pton(AF_INET, val_key, &(new_filter->src_ipv4));
            if (result<=0) {
                perror("error: Not in presentation format");
                printf("%s|%s\n",
                    val_key, inet_ntoa(new_filter->src_ipv4));
                strcpy(message, "Error: filter src_ipv4: not in presentation format\n");
                return false;
            }
            new_filter->flags.src_ipv4_flag = 1;
        }
    return true;
}

bool
parse_dst_ipv4(const char *name_key, const char *val_key, struct filter *new_filter, char *message)
{
    if ((strcmp(name_key, "dst_ipv4") == 0) && (new_filter->flags.dst_ipv4_flag == 0))
        {
            int result = inet_pton(AF_INET, val_key, &(new_filter->dst_ipv4));
            if (result<=0) {
                perror("error: Not in presentation format");
                printf("%s|%s\n",
                    val_key, inet_ntoa(new_filter->dst_ipv4));
                strcpy(message, "Error: filter dst_ipv4: not in presentation format\n");
                return false;
            }
            new_filter->flags.dst_ipv4_flag = 1;
        }
    return true;
}

bool
parse_dst_mac(const char *name_key, const char *val_key, struct filter *new_filter, char *message)
{
    if ((strcmp(name_key, "dst_mac") == 0) && (new_filter->flags.dst_mac_flag == 0))
        {
            struct ether_addr *mac = &(new_filter->dst_mac);
            if (!parse_mac(val_key, mac))
            {
                strcpy(message, "Error: filter dst_mac \n");
                return false;
            }
            new_filter->flags.dst_mac_flag = 1;
        }
    return true;
}

bool
parse_src_mac(const char *name_key, const char *val_key, struct filter *new_filter, char *message)
{
    if ((strcmp(name_key, "src_mac") == 0) && (new_filter->flags.src_mac_flag == 0))
        {
            struct ether_addr *mac = &(new_filter->src_mac);
            if (!parse_mac(val_key, mac))
            {
                strcpy(message, "Error: filter src_mac \n");
                return false;
            }
            new_filter->flags.src_mac_flag = 1;
        }
    return true;
}

bool
parse_ip_protocol(const char *name_key, const char *val_key, struct filter *new_filter, char *message)
{
    if ((new_filter->flags.ip_protocol_flag != 0))
    {
        //FIXME: the message can be rewrating. use strncat and and new sz_message or snprintf
        //FIXME: in other handles make 2: if- else if
        strcpy(message, "Error: ip protocol is set already \n");
        return true;
    }
    else if (strcmp(name_key, "ip_protocol") == 0)
        {
            new_filter->ip_protocol = (uint8_t)strtoul(val_key, NULL, 0);
            new_filter->flags.ip_protocol_flag = 1;
        }
    return true;
}

bool
parse_ether_type(const char *name_key, const char *val_key, struct filter *new_filter, char *message)
{
    if (new_filter->flags.ether_type_flag != 0)
    {
        strcpy(message, "Error: ether type is set already. will be ignored \n");
        return true;
    }
    else if ((strcmp(name_key, "ether_type") == 0) && (new_filter->flags.ether_type_flag == 0))
        {
            new_filter->ether_type = htons((uint16_t)strtoul(val_key, NULL, 0));
            new_filter->flags.ether_type_flag = 1;
        }
    return true;
}

bool
parse_src_tcp(const char *name_key, const char *val_key, struct filter *new_filter, char *message)
{
    if (new_filter->flags.src_tcp_flag != 0){
        strcpy(message, "Error: src tcp is set already. will be ignored \n");
        return true;
    }
    else if (strcmp(name_key, "src_tcp") == 0)
    {
        new_filter->src_tcp = htons((uint16_t)strtoul(val_key, NULL, 0));
        new_filter->flags.src_tcp_flag = 1;
    }
    return true;
}

bool
parse_dst_tcp(const char *name_key, const char *val_key, struct filter *new_filter, char *message)
{
    if (new_filter->flags.dst_tcp_flag != 0){
        strcpy(message, "Error: dst tcp is set already. will be ignored \n");
        return true;
    }
    else if (strcmp(name_key, "dst_tcp") == 0)
    {
        new_filter->dst_tcp = htons((uint16_t)strtoul(val_key, NULL, 0));
        new_filter->flags.dst_tcp_flag = 1;
    }
    return true;
}

bool
parse_src_udp(const char *name_key, const char *val_key, struct filter *new_filter, char *message)
{
    if (new_filter->flags.src_udp_flag != 0){
        strcpy(message, "Error: src udp is set already. will be ignored \n");
        return true;
    }
    else if (strcmp(name_key, "src_udp") == 0)
    {
        new_filter->src_udp = htons((uint16_t)strtoul(val_key, NULL, 0));
        new_filter->flags.src_udp_flag = 1;
    }
    return true;
}

bool
parse_dst_udp(const char *name_key, const char *val_key, struct filter *new_filter, char *message)
{
    if (new_filter->flags.dst_udp_flag != 0){
        strcpy(message, "Error: dst udp is set already. will be ignored \n");
        return true;
    }
    else if (strcmp(name_key, "dst_udp") == 0)
    {
        new_filter->dst_udp = htons((uint16_t)strtoul(val_key, NULL, 0));
        new_filter->flags.dst_udp_flag = 1;
    }
    return true;
}

bool
parse_vlan_id(const char *name_key, const char *val_key, struct filter *new_filter, char *message)
{
    if (new_filter->flags.vlan_id_flag != 0){
        strcpy(message, "Error: vlan flag is set already. will be ignored \n");
        return true;
    }
    else if (strcmp(name_key, "vlan_id") == 0)
    {
        new_filter->vlan_id = (uint16_t)strtoul(val_key, NULL, 0);
        new_filter->flags.vlan_id_flag = 1;
    }
    return true;
}

bool
parse_interface(const char *name_key, const char *val_key, struct filter *new_filter, char *message)
{
    if (new_filter->flags.interface_flag != 0){
        strcpy(message, "Error: interface is set already. will be ignored \n");
        return true;
    }
    else if (strcmp(name_key, "interface") == 0)
    {
        new_filter->interface = if_nametoindex(val_key);
        new_filter->flags.interface_flag = 1;
    }
    return true;
}