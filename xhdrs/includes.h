#ifndef INCLUDES_H
#define INCLUDES_H

#include <signal.h>
#include <stdint.h>

#define DEBUG 1

#define SINGLE_INSTANCE_PORT "31337"

#define STDIN   0
#define STDOUT  1
#define STDERR  2

#define FALSE   0
#define TRUE    1
typedef char BOOL;

typedef uint32_t ipv4_t;
typedef uint16_t port_t;

ipv4_t LOCAL_ADDR;

#define INET_ADDR(o1,o2,o3,o4)(htonl((o1 << 24)|(o2 << 16)|(o3 << 8)|(o4 << 0)))

#endif /* packet_h */
