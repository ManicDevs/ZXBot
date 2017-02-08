#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <time.h>

enum
{
	PING,
	PONG,
	VERSION,
	MESSAGE
};

struct Message
{
	uint16_t length;		// Length of payload
	char sha256[65];		// Sha256 of payload
	char payload[256];		// Message data payload
} message_t;

struct Packet
{
	int type;				// Type of message
	time_t timestamp;		// Timestamp of packet
	struct Message msg;		// Packet message structure
} packet_t;

#endif /* packet_h */
