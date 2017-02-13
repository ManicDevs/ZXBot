#define _GNU_SOURCE

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "xhdrs/includes.h"
#include "xhdrs/packet.h"
#include "xhdrs/utils.h"

extern uint32_t table_key;
extern sig_atomic_t exiting;

#ifdef DEBUG
void util_msgc(const char *type, const char *fmt, ...)
{
	char fmtbuf[128] = "";
	va_list args;
		
	va_start(args, fmt);
	snprintf(fmtbuf, sizeof(fmtbuf), "[%s] %s\r\n", type, fmt);
	vprintf(fmtbuf, args);
	va_end(args);
}
#endif

void util_sleep(int tosleep)
{
	time_t timer_loop;
#ifdef DEBUG
	util_msgc("Info", "Sleeping for %d second(s).", tosleep);
#endif
	timer_loop = time(NULL);
	while(time(NULL) - timer_loop <= tosleep)
	{
		if(exiting)
			break;
		sleep(1);
	}
}

int util_memsearch(char *buffer, int buflen, char *mem, int memlen)
{
    int i, matched = 0;

    if(memlen > buflen)
        return -1;

    for(i = 0; i < buflen; i++)
    {
        if(buffer[i] == mem[matched])
        {
            if(++matched == memlen)
                return i + 1;
        }
        else
            matched = 0;
    }

    return -1;
}

void util_strxor(char out[], void *_buf, int len)
{
    int i;
	unsigned char *buf = (unsigned char *)_buf; //, *out = malloc(len + 128);
	
	uint8_t k1 = table_key & 0xff,
            k2 = (table_key >> 8) & 0xff,
            k3 = (table_key >> 16) & 0xff,
            k4 = (table_key >> 24) & 0xff;
	
    for(i = 0; i < len; i++)
    {
        char tmp = buf[i] ^ k1;
        tmp ^= k2;
        tmp ^= k3;
        tmp ^= k4;

        out[i] = tmp;
    }
}

/*
void util_trim(char *str)
{
    int i, begin = 0, end = strlen(str) - 1;
	
    while(isspace(str[begin]))
		begin++;
	
    while((end >= begin) && isspace(str[end]))
		end--;
	
    for(i = begin; i <= end; i++)
		str[i - begin] = str[i];
	
    str[i - begin] = '\0';
}
*/

/*
uint16_t util_crc32(const uint8_t data)
{
    uint16_t checksum = 0;
    uint8_t  bit_index = 0;
    uint8_t  bit_value = 0;
	
    while(bit_index < 8)   
    {
        bit_value = 1 << bit_index++;
        checksum += (data & bit_value) ? bit_value : -1;
    }
	
    return checksum;
}
*/

char *util_fdgets(int sockfd, char *buffer, int buflen)
{
	int got = 0, total = 0;
	do
	{
		got = read(sockfd, buffer + total, 1);
		total = got == 1 ? total + 1 : total;
	}
	while (got == 1 && total < buflen && *(buffer + (total - 1)) != '\n');
	
	return total == 0 ? NULL : buffer;
}

char *util_type2str(int type)
{
	switch(type)
	{
		case PING:
			return "PING";
		case PONG:
			return "PONG";
		case MESSAGE:
			return "MESSAGE";
		default:
			return "<unknown>";
	}
}
