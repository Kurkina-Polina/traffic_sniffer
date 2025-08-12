#ifndef DEFINITIONS_H
#define DEFINITIONS_H
#include <stdio.h>
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