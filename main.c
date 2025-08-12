/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2022 OKTET Labs Ltd. All rights reserved. */
/** @file
 * @brief Network traffic analyzer tool.
 *
 * Chip-specific primitive implementation.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "checkers.h"
#include "filter.h"
#include "definitions.h"

/* Is used for creating message from server. */
#define BUFFER_SIZE (16*1024)

/* Indicator if socket is invalid. */
#define INVALID_SOCKET (-1)
/* Indexes of sockets for poll. */
enum {
    SNIFFER_INDEX = 0,      /* socket capturing all packets and filtering them */
    LISTEN_INDEX = 1,       /* socket listening for incoming connections */
    CLIENT_INDEX = 2        /* for client communication */
};

/* Flag for end program. */
static volatile bool keep_running = 1;

/* Count of all possible keys. */
const size_t size_keys = 10;


/**
 *  Returns message that contains API info that client may use
 */
static char const*
get_help_message()
{
    return "Usage: "
    "add <key> <value>  <key> <value> - add filter\n"
    "print - print statics on filters\n"
    "exit - to close connection\n"
    "del <number of filter> - delete filter by number - not supported yet\n"
    "\n"
    "possible keys:\n"
    "src_mac\n"
    "dst_mac\n"
    "ether_type\n "
    "ip_protocol\n"
    "dst_ipv4\n"
    "src_ipv4\n"
    "dst_ipv6 not supported yet\n"
    "src_ipv6 not supported yet\n"
    "src_tcp\n"
    "dst_tcp\n"
    "src_udp\n"
    "dst_udp\n"
    "\n"
    "On one filter you can use only one same keys:"
    " you can't use key dst_udp twice. Only last will work.\n"
    "Maximum count of filters is 10\n";
}

/**
 * Print MAC address.
 *
 * @param addr    MAC address in uint8_t
 */
static void
print_mac_addr(uint8_t const *addr)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
        addr[0], addr[1], addr[2],addr[3],addr[4],addr[5]);
}

/**
 * Print data of a packet like hexdump.
 *
 * @param data    pointer of start data
 * @param size    size of data
 */
static void
print_payload(char const *data, size_t size)
{
    if (size <=0 )
    {
        printf("No payload");
        return;
    }
    for (size_t i = 0; i < size; i++)
    {
        if (i % 16 == 0)
            printf("%04zx:  ", i);

        printf("%02x ", (unsigned char)data[i]);

        if (i % 16 == 15 || i == size - 1)
        {
            if (i % 16 != 15)
                for (size_t j = 0; j < 15 - (i % 16); j++)
                    printf("   ");

            printf("  |");

            size_t line_start = i - (i % 16);
            for (size_t j = line_start; j <= i; j++)
            {
                if (data[j] >= 32 && data[j] <= 126)
                    printf("%c", data[j]);
                else
                    printf(".");
            }

            printf("|\n");
        }
    }
}

/**
 * Print tcp header of a packet.
 *
 * @param buffer    full buffer, received from client
 * @param bufflen   size of buffer
 * @param iphdrlen  size of ip header in bytes
 *
 * @sa print_payload
 */
static void
tcp_header(char const *buffer, size_t bufflen, size_t iphdrlen)
{
    struct tcphdr const *tcp = (struct tcphdr const*)(buffer +
        iphdrlen + sizeof(struct ethhdr));
    printf("tcp Header \n");
    printf("Source tcp         :   %u\n", ntohs(tcp->th_sport));
    printf("Destination tcp    :   %u\n", ntohs(tcp->th_dport));
    char const *tcp_data = buffer + sizeof(struct ethhdr) + iphdrlen + tcp->th_off*IHL_WORD_LEN;
    size_t message_len = bufflen - (sizeof(struct ethhdr) + iphdrlen + tcp->th_off*IHL_WORD_LEN);
    printf("tcp payload        :   %ld bytes\n",  message_len);
    print_payload(tcp_data, message_len);
    printf("\n###########################################################");
    printf("\n\n ");
}

/**
 * Print udp header of a packet.
 *
 * @param buffer    full buffer, received from client
 * @param bufflen   size of buffer
 * @param iphdrlen  size of ip header in bytes
 *
 * @sa print_payload
 */
void
udp_header(char const *buffer, size_t bufflen, size_t iphdrlen)
{
    static size_t const udp_header_len = 8;
    struct udphdr const *udp = (struct udphdr const*)(buffer
        + iphdrlen + sizeof(struct ethhdr));
    printf("udp Header \n");
    printf("Source udp         :   %u\n", ntohs(udp->uh_sport));
    printf("Destination udp    :   %u\n", ntohs(udp->uh_dport));
    char const *udp_data = buffer + sizeof(struct ethhdr) + iphdrlen + udp_header_len;
    size_t message_len = bufflen - (sizeof(struct ethhdr) + iphdrlen + udp_header_len);
    printf("udp payload        :   %ld bytes\n",  message_len);
    print_payload(udp_data, message_len);
    printf("\n###########################################################");
    printf("\n\n ");
}


/**
 * Print ip header of a packet.
 *
 * @param buffer    full buffer, received from client
 * @param buf_flen   size of buffer
 *
 * @sa tcp_header udp_header
 */
void
ip_header(char const *buffer, size_t buf_flen)
{
    struct ip const *const ip_head = (struct ip const*)(buffer
        + sizeof(struct ether_header));
    printf("ip Header\n");
    printf("Version           :    %u\n", ip_head->ip_v);
    printf("header length     :    %u\n", ip_head->ip_hl);
    printf("Type of service   :    %u\n", ip_head->ip_tos);
    printf("protocol          :    %u\n", ip_head->ip_p);
    printf("Source ip         :    %s\n", inet_ntoa(ip_head->ip_src));
    printf("Destination ip    :    %s\n",inet_ntoa(ip_head->ip_dst));

    switch(ip_head->ip_p) {

        case IPPROTO_TCP:
            tcp_header(buffer, buf_flen, ip_head->ip_hl*IHL_WORD_LEN);
            break;

        case IPPROTO_UDP:
            udp_header(buffer, buf_flen, ip_head->ip_hl*IHL_WORD_LEN);
            break;

        default:
            printf("\n\n");
    }
}

/**
 * Print all headers of packet and data.
 *
 * @param buffer    full buffer, received from client
 * @param bufflen   size of buffer
 *
 * @sa ip_header
 */
void
print_packet(char const *buffer, size_t bufflen)
{
    printf("Ethernet Header \n");
    struct ether_header const *const ether = (struct ether_header const*)buffer;
    printf("Destination MAC   :    ");
    print_mac_addr(ether->ether_dhost);
    printf("Sourse      MAC   :    ");
    print_mac_addr(ether->ether_shost);

    printf("Ether type        :    %u\n", ntohs(ether->ether_type));

    switch(ntohs(ether->ether_type))
    {
        case ETHERTYPE_IP:
            ip_header(buffer, bufflen);
            break;

        default:
            break;
    }
}






/**
 * Check if the packet is suit for any filters.
 *
 * @param buffer              full buffer, received from client
 * @param bufflen             size of buffer
 * @param filters             all setted filters
 * @param filters_len         count of setted filters
 *
 * @sa                        check_mac check_ipv4 check_ip_protocol
 *                            check_ether_type check_tcp check_udp
 *
 * @todo                      add checks for vlan id, ipv6, interfaces
 */
static void
data_process(char const *buffer, size_t bufflen,
                  struct filter* filters, size_t filters_len)
{
    //FIXME: move to the top
    bool (*array_checks[])(char const *buffer, size_t bufflen, struct filter cur_filter) = {
    check_dst_mac, check_src_mac, check_dst_ipv4, check_src_ipv4, check_ip_protocol,
    check_ether_type, check_src_tcp, check_dst_tcp, check_src_udp, check_dst_udp
    };

    for (size_t i = 0; i < filters_len; i++)
    {
        for (size_t j = 0; j < size_keys; j++){
            if (!array_checks[j](buffer, bufflen, filters[i]))
                goto on_fail;
        }
        filters[i].count_packets += 1;
        filters[i].size += bufflen;
        DPRINTF("SUITABLE    +1 packet on filter %zu: %ld\n",
            i, filters[i].count_packets);
        print_packet(buffer, bufflen);
        continue;
on_fail:
        DPRINTF("NOT SUITABLE  %ld\n", filters[i].count_packets);
        print_packet(buffer, bufflen);
    }
}

/**
 * Make message about all statistics
 *
 * @param filters                  all setted filters
 * @param filters_len              count of setted filters
 * @param message[out]             statistics by every filter
 * @param message_sz [in]          size of message of statistics
 *
 */
static void
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

/**
 * Parse MAC address from string to struct of ether header.
 *
 * @param str                  string contain mac address
 * @param mac[out]             parsed mac address
 *
 */
static bool
parse_mac(const char *str, struct ether_addr *mac)
{
    return sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                 &mac->ether_addr_octet[0], &mac->ether_addr_octet[1],
                 &mac->ether_addr_octet[2], &mac->ether_addr_octet[3],
                 &mac->ether_addr_octet[4], &mac->ether_addr_octet[5]) == 6;
}

static bool
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

static bool
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

static bool
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

static bool
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

static bool
parce_ip_protocol(const char *name_key, const char *val_key, struct filter *new_filter, char *message)
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

static bool
parce_ether_type(const char *name_key, const char *val_key, struct filter *new_filter, char *message)
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

static bool
parce_src_tcp(const char *name_key, const char *val_key, struct filter *new_filter, char *message)
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

static bool
parce_dst_tcp(const char *name_key, const char *val_key, struct filter *new_filter, char *message)
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

static bool
parce_src_udp(const char *name_key, const char *val_key, struct filter *new_filter, char *message)
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

static bool
parce_dst_udp(const char *name_key, const char *val_key, struct filter *new_filter, char *message)
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

/**
 * Splits the string into tokens and every token compare with keys.
 * Every key set in filers massive and set the flag indicating
 * what key is set. If key already is set, next key will be ignored.
 * If some key is invalid or other problems, function returns empty filter.
 *
 * @param buff                 string contain mac address
 * @param message[out]         message about the result of work
 * @param message_sz[in]       message size that have been set
 *
 * @todo                       add vlan_id, ipv6, interface
 *
 * @return filter              new one filter
 *
 */
static struct filter
add_filter(char *buff, char *message, size_t message_sz)
{
    bool (*array_parsers[])(const char *name_key, const char *val_key, struct filter *new_filter, char *message) = {
        parse_dst_mac, parse_src_mac, parse_dst_ipv4, parse_src_ipv4, parce_ip_protocol,
        parce_ether_type, parce_src_tcp, parce_dst_tcp, parce_src_udp, parce_dst_udp
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
        for (size_t i = 0; i < size_keys; i++)
        {
            DPRINTF("name_key |%s| val_key |%s| \n", name_key, val_key);
            if(!array_parsers[i](name_key, val_key, &new_filter, message))
                return empty_filter;
        }
        name_key = strtok(NULL, " ");
    }
    strcpy(message, "success\n");
    return new_filter;
}

/**
 * Delete filter by a number. Not supported yet
 */
char const*
delete_filter(char const *buff, struct filter *filters,  size_t *filters_len)
{
    return "Not supported\n";
}

/**
 * Send data to the file descriptor.
 *
 * @param fd                   file descriptor that receive info
 * @param data                 data to send
 * @param sz                   size of data
 *
 * @return                     0 if success errno if faild
 *
 */
int
do_send(int fd, char const *const data, size_t sz)
{
    size_t written_bytes = 0;
    for (; written_bytes != sz;) {
        ssize_t rc = send(fd, data + written_bytes,
            sz - written_bytes, MSG_DONTWAIT);
        if (rc <= 0)  {
            rc = rc ? errno : ENOTCONN;
            printf("Failed to send data: %s\n", strerror(rc));
            return rc;
        }
        written_bytes += rc;
    }
    return 0;
}

/**
 * Receive a packet on sock_client and process a data.
 * Calls a function by any command in the packet.
 * Send message to sock_client about the results.
 *
 * @param sock_client          opened socket that receive info
 * @param filters [out]        all set filters
 * @param filters_len [out]    count of filters set
 *
 */
static void
handle_client_event(int *const sock_client,
    struct filter *filters,  int *filters_len)
{
    char rx_buffer[BUFFER_SIZE] = {};
    static char message_send[BUFFER_SIZE];

    ssize_t const rc = read(*sock_client, rx_buffer, sizeof(rx_buffer));
    if (rc <= 0)
    {
        close(*sock_client);
        if (rc == 0)
        {
            printf("Client closed the connection during read\n");
        }
        *sock_client = INVALID_SOCKET;
        return;
    }

    DPRINTF("From client:\n%s\n", rx_buffer);

    if (strncmp(CMD_ADD, rx_buffer, sizeof(CMD_ADD) - 1) == 0)
    {
        struct filter new_filter = add_filter(rx_buffer,
            message_send, sizeof(message_send));
        struct filter empty_filter = {0};
        if (memcmp(&new_filter, &empty_filter, sizeof(new_filter)) != 0) {
            filters[*filters_len] = new_filter;
            *filters_len +=1;
        }
        else
        {
            //FIXME: use strcat instead
            strcpy(message_send, get_help_message());
        }
    }
    else if (strncmp(CMD_DEL, rx_buffer, sizeof(CMD_DEL) - 1) == 0)
        strcpy(message_send, delete_filter(rx_buffer, filters, filters_len));

    else if (strncmp(CMD_PRINT, rx_buffer, sizeof(CMD_PRINT) - 1) == 0)
        get_statistics(filters, *filters_len, message_send,
            sizeof(message_send));
    else if (strncmp(CMD_EXIT, rx_buffer, sizeof(CMD_EXIT) - 1) == 0)
    {
        strcpy(message_send, "exiting\n");
        do_send(*sock_client, message_send, strlen(message_send));
        if (close(*sock_client) == -1)
            perror("Error in close connection: ");
        *sock_client = INVALID_SOCKET;
        return;
    }
    else
        strcpy(message_send, get_help_message());

    if (do_send(*sock_client, message_send, strlen(message_send)) != 0)
    {
        if (close(*sock_client) == -1)
            perror("Error in close connection: ");
        *sock_client = INVALID_SOCKET;
        return;
    }
}

/**
 * Set up sockets, addresses and structure for poll.
 *
 * @param fds                  opened socket that receive info
 * @param port_server          port on which server works
 * @param ip_server            ip address on which server works
 *
 * @return                     0 if success and -1 if fail
 *
 */
int
setup_sockets(struct pollfd *fds,
    uint16_t port_server, uint32_t ip_server)
{
    int sock_sniffer;
    int sock_listen;
    struct sockaddr_in servaddr = {
        .sin_family = AF_INET,
        .sin_addr = { .s_addr = ip_server, },
        .sin_port = port_server,
    };

    if ((sock_sniffer = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("failed to create sniffer socket\n");
        return errno;
    }
    if ((sock_listen = socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0)) < 0) {
        perror("failed to create listen socket\n");
        close(sock_sniffer);
        return errno;
    }


    if (setsockopt(sock_listen, SOL_SOCKET, SO_REUSEADDR,
        &(int){1}, sizeof(int)) < 0)
    {
        perror("setsockopt(SO_REUSEADDR) failed");
        //FIXME: make another commit why no return?
    }

    if ((bind(sock_listen, (struct sockaddr*)&servaddr, sizeof(servaddr))) != 0)
    {
        perror("socket bind failed...\n");
        close(sock_sniffer);
        close(sock_listen);
        return -1;
    }

    if ((listen(sock_listen, 5)) != 0)
    {
        perror("Listen failed...\n");
        close(sock_sniffer);
        close(sock_listen);
        return -1;
    }

    fds[SNIFFER_INDEX].fd = sock_sniffer;
    fds[SNIFFER_INDEX].events = POLL_IN;
    fds[LISTEN_INDEX].fd = sock_listen;
    fds[LISTEN_INDEX].events = POLL_IN;
    fds[CLIENT_INDEX].fd = INVALID_SOCKET;
    fds[CLIENT_INDEX].events = POLL_IN;

    return 0;
}

/**
 * Handle the listen socket if there is signal to connect.
 *
 * @param sock_listen          listening socket
 * @param sock_client          socket of client
 *
 */
static void
handle_listen(int* sock_listen, int* sock_client)
{

    socklen_t sock_client_len = sizeof(struct sockaddr_in);
    struct sockaddr_in clientaddr;
    int fd = accept(*sock_listen, (struct sockaddr*)&clientaddr, &sock_client_len);
    if (fd == -1)
    {
        perror("Failed to accept connection");
        return;
    }

    if (*sock_client != -1)
    {
        static char const already_busy_message[] = "Failed to accept"
                                                   " connection since there is already opened one\n";
        printf("%s", already_busy_message);
        do_send(fd, already_busy_message, sizeof(already_busy_message));
        if (close(fd) == 0)
            perror("Error in close connection: ");
        return;
    }
    printf("Connection accepted\n");
    *sock_client = fd;
}

/**
 * Cycle for poll.
 *
 * @param fds                  opened socket that receive info
 * @param count_sockets        count of all sockets in poll
 *
 */
static void
poll_loop(struct pollfd *fds, size_t const count_sockets)
{
    static char buffer[BUFFER_SIZE];
    int filters_len = 0;
    struct filter *filters = (struct filter *)malloc(
        sizeof(struct filter) * MAX_FILTERS);
    if (!filters)
    {
        perror("Error in malloc");
        return;
    }

    while (keep_running)
    {
        static int const timeout_ms = 200;
        int count_poll = poll(fds,  count_sockets, timeout_ms);
        if (count_poll == -1)
        {
            perror("poll error");
            free(filters);
            return;
        }

        if (count_poll == 0)
        {
            continue;
        }

        if (fds[SNIFFER_INDEX].revents & POLL_IN)
        {
            ssize_t const receive_count = read(fds[SNIFFER_INDEX].fd, buffer, sizeof(buffer));

            if (receive_count < 0)
            {
                perror("error in reading recvfrom function\n");
                free(filters);
                return;
            }
            data_process(buffer, receive_count, filters, filters_len);
        }

        if (fds[LISTEN_INDEX].revents & POLL_IN)
        {
            handle_listen(&fds[LISTEN_INDEX].fd, &fds[CLIENT_INDEX].fd);
        }

        if (fds[CLIENT_INDEX].revents & POLL_IN) {
            handle_client_event(&fds[CLIENT_INDEX].fd, filters, &filters_len);
        }

        if (fds[CLIENT_INDEX].revents & POLLHUP || fds[CLIENT_INDEX].revents & POLLERR)
        {
            printf("closing connection\n");
            if (!close(fds[CLIENT_INDEX].fd))
                perror("Error in close connection: ");
            fds[CLIENT_INDEX].fd = INVALID_SOCKET;
        }
    }
    free(filters);
}

/**
 * Process arguments.
 *
 * @param argc
 * @param argv
 * @param ip_server[out]       pointer to write ip address of server
 * @param port_server[out]     pointer to write tcp port of server
 *
 */
void
command_line(int argc, char *argv[], struct in_addr *ip_server,
    uint16_t *port_server)
{
    for (int opt;(opt = getopt(argc, argv, "a:p:h:")) != -1;) {
        switch (opt)
        {
            case 'a':
                if (inet_pton(AF_INET, optarg, ip_server) <= 0)
                {
                    fprintf(stderr, "Invalid value for ip address\n");
                    exit(EXIT_FAILURE);
                }
                break;

            case 'p':
                *port_server = htons((uint16_t)strtoul(optarg, NULL, 0));
                break;
            case 'h':
            default:
                fprintf(stderr, "Usage: %s -a <IP> -p <PORT>\n", argv[0]);
                exit(opt == 'h' ? EXIT_SUCCESS : EXIT_FAILURE);
        }
    }
    //FIXME: why twise?
    if (ip_server->s_addr == 0) {
        fprintf(stderr, "Usage: %s -a <IP> -p <PORT>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    if (port_server == 0) {
        fprintf(stderr, "Usage: %s -a <IP> -p <PORT>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    printf("starting on %s and on port %u\n",
        inet_ntoa(*ip_server), ntohs(*port_server));
}

/**
 * Handler for interrupt by SIGINT.
 */
static void
sig_handler(int unused)
{
    keep_running = 0;
}

int
main(int argc, char *argv[])
{
    struct in_addr ip_server = {0};
    uint16_t port_server = 0;
    struct pollfd fds[3];

    signal(SIGINT, sig_handler);
    command_line(argc, argv, &ip_server, &port_server);

    if (setup_sockets(fds, port_server, ip_server.s_addr) != 0)
        return EXIT_FAILURE;

    poll_loop(fds, ARRAY_SIZE(fds));
    return 0;
}
