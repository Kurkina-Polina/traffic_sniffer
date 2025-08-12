#ifndef CHECKERS_H
#define CHECKERS_H
#include "filter.h"
#include "definitions.h"
#include <stdbool.h>
#include <stddef.h>


bool
check_src_mac(char const *buffer, size_t bufflen, struct filter cur_filter);

bool
check_dst_mac(char const *buffer, size_t bufflen, struct filter cur_filter);

bool
check_ether_type(char const *buffer, size_t bufflen, struct filter cur_filter);

bool
check_src_ipv4(char const *buffer, size_t bufflen,
    struct filter cur_filter);

bool
check_dst_ipv4(char const *buffer, size_t bufflen, struct filter cur_filter);

bool
check_ip_protocol(char const *buffer, size_t bufflen,
    struct filter cur_filter);

bool
check_dst_tcp(char const *buffer, size_t bufflen,
    struct filter cur_filter);

bool
check_src_tcp(char const *buffer, size_t bufflen,
    struct filter cur_filter);

bool
check_dst_udp(char const *buffer, size_t bufflen,
struct filter cur_filter);

bool
check_src_udp(char const *buffer, size_t bufflen,
    struct filter cur_filter);

#endif