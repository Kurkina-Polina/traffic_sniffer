#include<stdio.h>
#include <stdlib.h>
#include<string.h>
#include<signal.h>
#include<stdbool.h>
#include <poll.h>

#include<sys/socket.h>
#include<sys/types.h>
#include <unistd.h>
#include<linux/if_packet.h>

#include<netinet/in.h>
#include<netinet/if_ether.h>
#include<netinet/ip.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
#include<arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <netinet/in.h>
#include <net/ethernet.h>

/* MAX_PORTS is used for creating buffer that reads packet from spinning socket. */
#define MAX_PORTS 65536
/* Is used for creating message from server. */
#define MAX_MESSAGE 1000
/* Temporary solution to create filters list. */
#define MAX_FILTERS 10
// FIXME:
/* Temporary silution to start server on that port. */
#define PORT 8080

#define IHL_WORD_LEN 4

/* Temporary function to print progress of work. */
#define DPRINTF(...) printf(__VA_ARGS__)

/* Flag for end program. */
static volatile bool keep_running = 1;
/* Flag to indicate start new connection with client or not. */
static bool is_already_established = 0;

/* Bitmask flags indicating which filter types are active. */
struct filter_flag
{
    bool vlan_id_flag;
    bool dst_mac_flag;
    bool src_mac_flag;
    bool ether_type_flag;
    bool dst_ipv4_flag;
    bool src_ipv4_flag;
    bool dst_ipv6_flag;
    bool src_ipv6_flag;
    bool ip_protocol_flag;
    bool dst_tcp_flag;
    bool src_tcp_flag;
    bool dst_udp_flag;
    bool src_udp_flag;
};

/* Filter contains or not keys. */
struct filter
{
    uint16_t vlan_id;
    struct ether_addr dst_mac;
    struct ether_addr src_mac;
    uint16_t ether_type;
    struct in_addr dst_ipv4;
    struct in_addr src_ipv4;
    struct in6_addr dst_ipv6;
    struct in6_addr src_ipv6;
    uint8_t ip_protocol;
    uint16_t dst_tcp;
    uint16_t src_tcp;
    uint16_t dst_udp;
    uint16_t src_udp;

    size_t count_packets;
    size_t size;
    struct filter_flag flags;
};

/**
 *  Returns message that contains API info that client may use
 */
static char const* get_help_message()
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
    "On one filter you can use only one same keys: you can't use key dst_udp twise. Only last will work.\n"
    "Maximum size of filters is 10\n";
}

/**
 * Print MAC address.
 *
 * @param addr    MAC address in uint8_t
 */
static void print_mac_addr(uint8_t const* const addr)
{
    printf("%d:%d:%d:%d:%d:%d \n", addr[0], addr[1], addr[2],addr[3],addr[4],addr[5]);
}

/**
 * Hendler for interrupt by SIGINT.
 */
static void handler()
{
    keep_running = 0;
}

/**
 * Print data of a packet like hexdump.
 *
 * @param data    pointer of start data
 * @param size    size of data
 */
static void print_payload(char const* data, size_t size)
{
    if (size <=0 )
    {
        printf("No payload");
        return;
    }
    for (size_t i = 0; i < size; i++)
    {
        if (i % 16 == 0) {
            printf("%04zx:  ", i);
        }

        printf("%02x ", (unsigned char)data[i]);

        if (i % 16 == 15 || i == size - 1)
        {
            if (i % 16 != 15)
            {
                for (size_t j = 0; j < 15 - (i % 16); j++)
                {
                    printf("   ");
                }
            }

            printf("  |");

            size_t line_start = i - (i % 16);
            for (size_t j = line_start; j <= i; j++)
            {
                if (data[j] >= 32 && data[j] <= 126)
                {
                    printf("%c", data[j]);
                } else
                {
                    printf(".");
                }
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
static void tcp_header(char const* buffer, size_t bufflen, size_t iphdrlen)
{
    struct tcphdr const * tcp = (struct tcphdr const*)(buffer + iphdrlen + sizeof(struct ethhdr));
    printf("tcp Header \n");
    printf("Source tcp         :   %u\n", ntohs(tcp->th_sport));
    printf("Destination tcp    :   %u\n", ntohs(tcp->th_dport));
    char const* tcp_data = buffer + sizeof(struct ethhdr) + iphdrlen + tcp->th_off*4;
    size_t message_len = bufflen - (sizeof(struct ethhdr) + iphdrlen + tcp->th_off*4);
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
void udp_header(char const* buffer, size_t bufflen, size_t iphdrlen)
{
    static size_t const udp_header_len = 8;
    struct udphdr const *udp = (struct udphdr const*)(buffer + iphdrlen + sizeof(struct ethhdr));
    printf("udp Header \n");
    printf("Source udp         :   %u\n", ntohs(udp->uh_sport));
    printf("Destination udp    :   %u\n", ntohs(udp->uh_dport));
    char const* udp_data = buffer + sizeof(struct ethhdr) + iphdrlen + udp_header_len;
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
void ip_header(char const* buffer, size_t buf_flen)
{
    struct ip const* const ip_head = (struct ip const*)(buffer + sizeof(struct ether_header));
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
void print_packet(char const* buffer, size_t bufflen)
{
    printf("Ethernet Header \n");
    struct ether_header const* const ether = (struct ether_header const*)buffer;
    printf("Destination MAC   :    ");
    print_mac_addr(ether->ether_dhost);
    printf("Sourse      MAC   :    ");
    print_mac_addr(ether->ether_shost);

    printf("Ether type        :    %u\n", ntohs(ether->ether_type));

    switch(ntohs(ether->ether_type)) {
        case ETHERTYPE_IP:
            ip_header(buffer, bufflen);
            break;
        default:
            break;
    }
}

/**
 * Compare mac addresses.
 *
 * @param buffer              full buffer, received from client
 * @param bufflen             size of buffer
 * @param mac                 mac address with which comparing
 *
 * @return                    true if addresses are same and false else
 */
static bool check_mac(char const* buffer, size_t bufflen, struct ether_addr mac)
{
    struct ether_header const* const ether = (struct ether_header const*)buffer;
    uint8_t const* const addr = ether->ether_shost;
    return !memcmp(addr, mac.ether_addr_octet, ETHER_ADDR_LEN);
}

/**
 * Check ether type are same or not.
 *
 * @param buffer              full buffer, received from client
 * @param bufflen             size of buffer
 * @param ether_type          ether type address with which comparing
 *
 * @return                    true if addresses are same and false else
 */
bool check_ether_type(char const* buffer, int bufflen, uint16_t ether_type)
{
    struct ether_header const* const ether = (struct ether_header const*)buffer;
    uint16_t ether_data = ether->ether_type;
    if(ether_data != ether_type)
    {
        DPRINTF("it is not  %u != %u\n", ntohs(ether_data), ntohs(ether_type));
        return false;
    }
    return true;
}

/**
 * Check ipv4 adderesses are same or not.
 *
 * @param buffer              full buffer, received from client
 * @param bufflen             size of buffer
 * @param ipv                 ipv4 address with which comparing
 *
 * @return                    true if addresses are same and false else
 */
static bool check_ipv4(char const* buffer, size_t bufflen,  struct in_addr ipv, bool is_scr)
{
    struct ether_header const* const ether = (struct ether_header const*)buffer;
    if (ether->ether_type == ETHERTYPE_IP)
    {
        struct ip const* const ip_head = (struct ip const*)(buffer + sizeof(struct ether_header));
        if(is_scr)
        {
            if(ip_head->ip_src.s_addr == ipv.s_addr)
            {
                DPRINTF("it is %s=%s\n", inet_ntoa(ip_head->ip_src),  inet_ntoa(ipv));
                return true;
            }
        }
        else{
            if(ip_head->ip_dst.s_addr == ipv.s_addr)
            {
                DPRINTF("it is %s=%s\n", inet_ntoa(ip_head->ip_dst),  inet_ntoa(ipv));
                return true;
            }
        }
    }
    else
    {
        DPRINTF("it is not ipv4\n");
    }
    return false;
}

/**
 * Check ip protocols are same or not.
 *
 * @param buffer              full buffer, received from client
 * @param bufflen             size of buffer
 * @param ip_protocol         ip protocol with which comparing
 *
 * @todo                      add ipv6
 *
 * @return                    true if protocols are same and false else
 */
static bool check_ip_protocol(char const* buffer, size_t bufflen, uint8_t ip_protocol)
{
    struct ether_header const* const ether = (struct ether_header const*)buffer;
    if (ether->ether_type == ETHERTYPE_IP)
    {
        struct ip const* const ip_head = (struct ip const*)(buffer + sizeof(struct ether_header));
        if( ip_head->ip_p == ip_protocol)
        {
            DPRINTF("ip protocol is suitable %u\n", ip_head->ip_p);
            return true;
        }
    }
    else if(ether->ether_type == ETHERTYPE_IPV6)
    {
        /* It is ipv6. Will be done later*/
        return false;
    }
    return false;
}

/**
 * Check tcp ports are same or not.
 *
 * @param buffer              full buffer, received from client
 * @param bufflen             size of buffer
 * @param tcp_port            tcp port with which comparing
 * @param is_src              flag to indicate sourse or destination port*
 *
 * @todo                      add ipv6
 *
 * @return                    true if ports are same and false else
 */
static bool check_tcp(char const* buffer, size_t bufflen, uint16_t tcp_port, bool is_src)
{
    struct ether_header const* const ether = (struct ether_header const*)buffer;
    if (ether->ether_type == ETHERTYPE_IP)
    {
        struct ip const* const ip_head = (struct ip const*)(buffer + sizeof(struct ether_header));
        if (ip_head->ip_p == IPPROTO_TCP) //FIXME: dont use magic numbers
        {
            struct tcphdr *tcp = (struct tcphdr*)(buffer + ip_head->ip_hl*4 + sizeof(struct ethhdr));
            if (is_src && tcp->th_sport == tcp_port)
            {
                DPRINTF("tcp is suitable %u\n", ntohs(tcp->th_sport));
                return true;
            }
            else if( tcp->th_dport == tcp_port)
            {
                DPRINTF("tcp is suitable %u\n",ntohs(tcp->th_dport));
                return true;
            }
            else
            {
                DPRINTF("tcp not suit %u -> %u \n", ntohs(tcp->th_sport), ntohs(tcp->th_dport));
            }
        }
        else
        {
            /* IT is not tcp. */
            return false;
        }
    }
    else if(ether->ether_type == ETHERTYPE_IPV6)
    {
        /* It is ipv6. Will be done later*/
        return false;
    }
    return false;
}

/**
 * Check udp ports are same or not.
 *
 * ccc
 * @param udp_port            udp port with which comparing
 * @param is_src              flag to indicate sourse or destination port
 *
 * @todo                      add ipv6
 *
 * @return                    true if ports are same and false else
 */
bool check_udp(char const* buffer, size_t bufflen, uint16_t udp_port, bool is_src)
{
    struct ether_header const* const ether = (struct ether_header const*)buffer;
    if (ether->ether_type == ETHERTYPE_IP) //FIXME:
    {
        struct ip const* const ip_head = (struct ip const*)(buffer + sizeof(struct ether_header));
        if (ip_head->ip_p == IPPROTO_UDP)
        {

            struct udphdr *udp = (struct udphdr*)(buffer + ip_head->ip_hl*4 + sizeof(struct ethhdr));
            if (is_src && udp->uh_sport == udp_port)
            {
                DPRINTF("udp is suitable%u\n", ntohs(udp->uh_sport));
                return true;
            }
            else if( udp->uh_dport == udp_port)
            {
                DPRINTF("udp is suitable%u\n", ntohs(udp->uh_dport));
                return true;
            }
            else
            {
                DPRINTF("udp not suit %u->%u\n",ntohs(udp->uh_sport), ntohs(udp->uh_dport));
            }

        }
        else
        {
            /* It is not udp. */
            return false;
        }
    }
    else if(ether->ether_type == ETHERTYPE_IPV6)
    {
        /* It is ipv6. Will be done later*/
        return false;
    }
    return false;
}

/**
 * Check if the packet is suit for any filters/
 *
 * @param buffer              full buffer, received from client
 * @param bufflen             size of buffer
 * @param filters             all setted filters
 * @param filters_len         count of setted filters
 *
 * @sa                        check_mac check_ipv4 check_ip_protocol
 *                            check_ether_type check_tcp check_udp
 *
 * @todo                      add checks for vlan id and ipv6
 */
static void data_process(char const* buffer, size_t bufflen,
                  struct filter* filters, size_t filters_len)
{
    for (size_t i = 0; i < filters_len; i++)
    {
        if(filters[i].flags.dst_mac_flag)
        {
            if (!check_mac(buffer, bufflen, filters[i].dst_mac))
                goto on_fail;
        }
        if(filters[i].flags.src_mac_flag)
        {
            if (!check_mac(buffer, bufflen, filters[i].src_mac))
                goto on_fail;
        }
        if(filters[i].flags.ether_type_flag)
        {
            if (!check_ether_type(buffer, bufflen, filters[i].ether_type))
                goto on_fail;
        }
        if(filters[i].flags.dst_ipv4_flag)
        {
            if (!check_ipv4(buffer, bufflen, filters[i].dst_ipv4, false))
                goto on_fail;
        }
        if(filters[i].flags.src_ipv4_flag)
        {
            if (!check_ipv4(buffer, bufflen, filters[i].src_ipv4, true))
                goto on_fail;
        }
        if(filters[i].flags.ip_protocol_flag)
        {
            if (!check_ip_protocol(buffer, bufflen, filters[i].ip_protocol))
                goto on_fail;
        }
        if(filters[i].flags.dst_tcp_flag)
        {
            if (!check_tcp(buffer, bufflen, filters[i].dst_tcp, false))
                goto on_fail;
        }
        if(filters[i].flags.src_tcp_flag)
        {
            if (check_tcp(buffer, bufflen, filters[i].src_tcp, true))
                goto on_fail;
        }
        if(filters[i].flags.dst_udp_flag)
        {
            if (check_udp(buffer, bufflen, filters[i].dst_udp, false))
                goto on_fail;
        }
        if(filters[i].flags.src_udp_flag)
        {
            if (check_udp(buffer, bufflen, filters[i].src_udp, true))
                goto on_fail;
        }

        filters[i].count_packets += 1;
        filters[i].size += bufflen;
        DPRINTF("SUITABLE    +1 packet on filter %zu: %ld\n", i, filters[i].count_packets);
        print_packet(buffer, bufflen);
        continue;
on_fail:
        DPRINTF("NOT SUITABLE  %ld\n", filters[i].count_packets);
        print_packet(buffer, bufflen);
    }
}

static void get_statistics(struct filter* filters, size_t filters_len, char* message, size_t message_sz)
{
    if(filters_len<=0)
    {
        snprintf(message, message_sz, "No filters yet\n");
    }
    for (size_t i = 0; i < filters_len; i++)
    {
        snprintf(message, message_sz,
                "Filter number %zu: packets=%ld, total_size=%ld bytes\n",
                i + 1,
                filters[i].count_packets,
                filters[i].size);
    }
}


static bool parse_mac(const char* str, struct ether_addr* mac)
{
    return sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                 &mac->ether_addr_octet[0], &mac->ether_addr_octet[1],
                 &mac->ether_addr_octet[2], &mac->ether_addr_octet[3],
                 &mac->ether_addr_octet[4], &mac->ether_addr_octet[5]) == 6;
}

static struct filter add_filter(char* buff, char* message, size_t message_sz)
{
    char* end = strchr(buff, '\r');
    //FIXME:
    if (end)
    {
        *end = 0;
    } else
    {
        end = strchr(buff, '\n');
        if (end)
            *end = 0;
    }
    struct filter new_filter = {0};

    char* token = strtok(buff + strlen("add"), " ");
    if (!token)
    {
        strcpy(message, "Error: No filter parameters\n");
        return new_filter;
    }

    while (token != NULL)
    {
        char* next_token = strtok(NULL, " ");
        if (!next_token) {
            strcpy(message, "Error: No filter\n");
            return new_filter;
        }

        if (strcmp(token, "dst_mac") == 0)
        {
            if (!parse_mac(next_token, &new_filter.dst_mac))
            {
                strcpy(message, "Error: filter dst_mac\n");
                return new_filter;
            }
            new_filter.flags.dst_mac_flag = 1;
        }
        else if (strcmp(token, "src_mac") == 0) {
            if (!parse_mac(next_token, &new_filter.src_mac))
            {
                strcpy(message, "Error: filter src_mac\n");
                return new_filter;
            }
            new_filter.flags.src_mac_flag = 1;
        }
        else if (strcmp(token, "ether_type") == 0)
        {
            new_filter.ether_type = htons((uint16_t)strtoul(next_token, NULL, 0));
            new_filter.flags.ether_type_flag = 1;
        }
        else if (strcmp(token, "dst_ipv4") == 0)
        {
            int result = inet_pton(AF_INET, next_token, &new_filter.dst_ipv4);
            if (!result)
            {
                printf("error: Not in presentation format %s  %s\n ", next_token, inet_ntoa(new_filter.dst_ipv4));
                strcpy(message, "Error: filter dst_ipv4: not in presentation format\n");
                return new_filter;
            }
            if (result<0)
            {
                //FIXME: message is not filled
                perror("inet_pton error: ");
            }
            new_filter.flags.dst_ipv4_flag = 1;
        }
        else if (strcmp(token, "src_ipv4") == 0) {
            int result = inet_pton(AF_INET, next_token, &new_filter.src_ipv4);
            if (!result)
            {
                printf("error: Not in presentation format %s  %s\n ", next_token, inet_ntoa(new_filter.src_ipv4));
                strcpy(message, "Error: filter dst_ipv4: not in presentation format\n");
                return new_filter;
            }
            if (result<0)
            {
                //FIXME: message is not filled
                perror("inet_pton error: ");
            }
            new_filter.flags.src_ipv4_flag = 1;
        }
        else if (strcmp(token, "ip_protocol") == 0)
        {
            new_filter.ip_protocol = (uint8_t)strtoul(next_token, NULL, 0);
            new_filter.flags.ip_protocol_flag = 1;
        }
        else if (strcmp(token, "src_tcp") == 0)
        {
            new_filter.src_tcp = htons((uint16_t)strtoul(next_token, NULL, 0));
            new_filter.flags.src_tcp_flag = 1;
        }
        else if (strcmp(token, "dst_tcp") == 0)
        {
            new_filter.dst_tcp = htons((uint16_t)strtoul(next_token, NULL, 0));
            new_filter.flags.dst_tcp_flag = 1;
        }
        else if (strcmp(token, "src_udp") == 0)
        {
            new_filter.src_udp = htons((uint16_t)strtoul(next_token, NULL, 0));
            new_filter.flags.src_udp_flag = 1;
        }
        else if (strcmp(token, "dst_udp") == 0)
        {
            new_filter.dst_udp = htons((uint16_t)strtoul(next_token, NULL, 0));
            new_filter.flags.dst_udp_flag = 1;
        }
        else
        {
            strcpy(message, get_help_message());
            return new_filter;
        }
        token = strtok(NULL, " ");
    }
    strcpy(message, "success\n");
    return new_filter;
}

char const* delete_filter(char* buff, struct filter* filters,  int* filters_len)
{
    return "not supported yet\n";
}

void input_from_client(int sock_client, struct filter* filters,  int* filters_len)
{
    char message_reseive[MAX_MESSAGE] = {};
    read(sock_client, message_reseive, sizeof(message_reseive));

    printf("From client: %s\t", message_reseive);
    static char message[MAX_MESSAGE];

    if (strncmp("add", message_reseive, 3) == 0)
    {
        filters[*filters_len] = add_filter(message_reseive, message, sizeof(message));
        *filters_len +=1;
    }

    else if (strncmp( "del", message_reseive, 3) == 0)
    {
        strcpy(message, delete_filter(message_reseive, filters, filters_len));
    }

    else if (strncmp("print", message_reseive,  5) == 0)
    {
        get_statistics(filters, *filters_len, message, sizeof(message));
    }
    else if (strncmp("exit", buff,  4) == 0)
    {
        strcpy(message, "exiting\n");
        keep_running = 0;
    }
    else
    {
        strcpy(message, get_help_message());
    }

    send(sock_client, message, strlen(message), MSG_NOSIGNAL);
}



int main(int argc, char* argv[])
{
    signal(SIGINT, handler);
    void* prev = signal(SIGPIPE, SIG_IGN);
    if (prev == SIG_ERR){
        return EXIT_FAILURE;
    }

    int sock_sniffer = -1;
    int sock_client = -1;
    int sock_listen = -1;
    int bufflen;
    int filters_len = 0;
    struct sockaddr_in servaddr, clientaddr;
    nfds_t count_sockets = 3;
    struct pollfd fds[count_sockets];

    char* buffer = (char *)malloc(MAX_PORTS);
    if (!buffer)
        goto on_fail;
    memset(buffer,0,MAX_PORTS);

    printf("starting .... \n");

    if ((sock_sniffer = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL))) < 0) {
        perror("failed to create sniffer socket\n");
        goto on_fail;
    }
    if ((sock_listen = socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0)) < 0) {
        perror("failed to create listen socket\n");
        goto on_fail;

    }

    if (setsockopt(sock_listen, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0){
        perror("setsockopt(SO_REUSEADDR) failed");
    }

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);

    if ((bind(sock_listen, (struct sockaddr*)&servaddr, sizeof(servaddr))) != 0)
    {
        perror("socket bind failed...\n");
        exit(0);
    }

    if ((listen(sock_listen, 5)) != 0)
    {
        perror("Listen failed...\n");
        exit(0);
    }

    // creating poll
    fds[0].fd = sock_sniffer;
    fds[0].events = POLL_IN;
    fds[1].fd = sock_listen;
    fds[1].events = POLL_IN;

    struct filter* filters = (struct filter *)malloc(sizeof(struct filter) * MAX_FILTERS);

    while(keep_running)
    {
        int count_poll = poll(fds,  count_sockets, -1);
        if (count_poll == -1)
        {
            perror("poll error");
            goto on_fail;
        }

        if(fds[0].revents & POLL_IN)
        {
            bufflen = read(sock_sniffer,buffer, MAX_PORTS);

            if(bufflen<0)
            {
                perror("error in reading recvfrom function\n");
                return -1;
            }
            data_process(buffer, bufflen, filters,  filters_len);
        }

        if(fds[1].revents & POLL_IN)
        {
            printf("server read signal to connect\nw");
            socklen_t sock_client_len;
            sock_client = accept(sock_listen, (struct sockaddr*)&clientaddr, &sock_client_len);
            if (is_already_established)
            {
                char message[] = "Already busy";
                memmove(buffer, message, sizeof(message));
                write(sock_client, buffer, sizeof(buffer));
                if (!close(sock_client))
                {
                    perror("Error in close connection: ");
                }
                continue;
            }
            fds[2].fd = sock_client;
            fds[2].events = POLL_IN;
            is_already_established = 1;
        }
        if(fds[2].revents & POLL_IN)
        {
            input_from_client(sock_client, filters, &filters_len);
        }
        if(fds[1].revents &POLLHUP||fds[1].revents &POLLERR)
        {
            printf("closing connection\n");
            is_already_established=0;
            if (!close(sock_client))
            {
                perror("Error in close connection: ");
            }
        }
    }

    close(sock_sniffer);
    if (!close(sock_sniffer))
    {
        perror("Error in close sniffer socket: ");
    }
    if (!close(sock_listen))
    {
        perror("Error in close listen socket: ");
    }
    if (!close(sock_client))
    {
        perror("Error in close client socket: ");
    }
    printf("DONE\n");
    return EXIT_SUCCESS;
on_fail:
    free(buffer);
    if (sock_sniffer != -1)
        close(sock_sniffer);
    if (sock_listen != -1)
        close(sock_listen);
    if (sock_client != -1)
        close(sock_client);
    return EXIT_FAILURE;
}
