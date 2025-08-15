#ifndef DEFINITIONS_H
#define DEFINITIONS_H
#include <stdio.h>
#include <stdbool.h>

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
#define KEYS_COUNT 12

/* Temporary solution to create filters list. */
#define MAX_FILTERS 10

/* Len of word in ip and tcp headers*/
#define IHL_WORD_LEN 4

/* Temporary function to print progress of work. */
#define DPRINTF(...) printf(__VA_ARGS__)

/* Control commands for intaction. */
#define CMD_ADD "add"       /* add new filter */
#define CMD_DEL "del"       /* delete filter */
#define CMD_EXIT "exit"     /* stop communication with server */
#define CMD_PRINT "print"   /* print information about packet on all filters */

/* Helper macros to get count of elements in the array. */
#define ARRAY_SIZE(a)  (sizeof(a) / sizeof((a)[0]))

#endif