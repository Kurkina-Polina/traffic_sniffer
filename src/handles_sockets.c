#include "handles_sockets.h"
#include "checkers.h"
#include "handles_user_input.h"
#include "parsers_packet.h"
#include "printers.h"
#include "get_help.h"
#include <errno.h>
#include <stdbool.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

/* Flag for end program. */
static volatile bool keep_running = 1;

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
 * Handler for interrupt by SIGINT.
 */
static void
sig_handler(int unused)
{
    keep_running = 0;
}

void
data_process(char const *buffer, size_t bufflen,
    struct filter* filters, size_t filters_len, struct sockaddr_ll sniffaddr)
{
    bool (*array_checks[])(struct filter packet_data, struct filter cur_filter) = {
    check_dst_mac, check_src_mac, check_dst_ipv4, check_src_ipv4, check_ip_protocol,
    check_ether_type, check_src_tcp, check_dst_tcp, check_src_udp, check_dst_udp, check_vlan_id,
    check_interface, check_dst_ipv6, check_src_ipv6,
    };

    struct filter packet_data = {0};

    parse_packet_ether(buffer, bufflen, &packet_data, sniffaddr);

    for (size_t i = 0; i < filters_len; i++)
    {
        for (size_t j = 0; j < KEYS_COUNT; j++){
            if (!array_checks[j](packet_data, filters[i]))
                goto on_fail;
        }
        filters[i].count_packets += 1;
        filters[i].size += bufflen;
        DPRINTF("\nSUITABLE    +1 packet on filter %zu: %ld\n",
            i, filters[i].count_packets);
        print_packet(buffer, bufflen, sniffaddr);
        continue;
on_fail:
        DPRINTF("\nNOT SUITABLE  %ld\n", filters[i].count_packets);
        print_packet(buffer, bufflen, sniffaddr);
    }
}

void
handle_client_event(int *const sock_client,
    struct filter *filters,  size_t *filters_len)
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
            if (do_send(*sock_client, get_help_message(), strlen(get_help_message())) != 0)
            {
                if (close(*sock_client) == -1)
                    perror("Error in close connection: ");
                *sock_client = INVALID_SOCKET;
                return;
            }
        }
    }
    else if (strncmp(CMD_DEL, rx_buffer, sizeof(CMD_DEL) - 1) == 0)
        delete_filter(rx_buffer, filters, filters_len, message_send);

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


void
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
        char const already_busy_message[] = "Failed to accept"
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

void
handle_sniffer(int sock_sniffer, struct filter *filters,  size_t filters_len)
{
    static char buffer[BUFFER_SIZE];
    struct sockaddr_ll snifaddr;
    socklen_t snifaddr_len;
    ssize_t const receive_count = recvfrom(sock_sniffer, buffer, sizeof(buffer), 0, (struct sockaddr*)&snifaddr, &snifaddr_len);

    if (receive_count < 0)
    {
        perror("error in reading recvfrom function\n");
        free(filters);
        return;
    }
    data_process(buffer, receive_count, filters, filters_len, snifaddr);
}

void
poll_loop(struct pollfd *fds, size_t const count_sockets)
{
    signal(SIGINT, sig_handler);
    
    size_t filters_len = 0;
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
            handle_sniffer(fds[SNIFFER_INDEX].fd, filters, filters_len);
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
        return errno;
    }

    if ((bind(sock_listen, (struct sockaddr*)&servaddr, sizeof(servaddr))) != 0)
    {
        perror("socket bind failed...\n");
        close(sock_sniffer);
        close(sock_listen);
        return errno;
    }

    if ((listen(sock_listen, 5)) != 0)
    {
        perror("Listen failed...\n");
        close(sock_sniffer);
        close(sock_listen);
        return errno;
    }

    fds[SNIFFER_INDEX].fd = sock_sniffer;
    fds[SNIFFER_INDEX].events = POLL_IN;
    fds[LISTEN_INDEX].fd = sock_listen;
    fds[LISTEN_INDEX].events = POLL_IN;
    fds[CLIENT_INDEX].fd = INVALID_SOCKET;
    fds[CLIENT_INDEX].events = POLL_IN;

    return 0;
}