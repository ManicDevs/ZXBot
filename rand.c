#define _GNU_SOURCE

#include <stdint.h>
#include <unistd.h>
#include <time.h>

#include "xhdrs/includes.h"
#include "xhdrs/rand.h"

static uint32_t x, y, z, w;

void rand_init(void)
{
	x = time(NULL);
	y = getpid() ^ getppid();
	z = clock();
	w = z ^ y;
}

uint32_t rand_next(void)
{
	uint32_t t = x;
	t ^= t << 11;
	t ^= t >> 8;
	x = y;
	y = z;
	z = w;
	w ^= w >> 19;
	w ^= t;
	
	return w;
}

void rand_str(char *buffer, int buflen)
{
	while(buflen > 0)
	{
		if(buflen >= 4)
		{
			*((uint32_t*)buffer) = rand_next();
			buffer += sizeof(uint32_t);
			buflen -= sizeof(uint32_t);
		}
		else if(buflen >= 2)
		{
			*((uint16_t*)buffer) = rand_next() & 0xFFFF;
			buffer += sizeof(uint16_t);
			buflen -= sizeof(uint16_t);
		}
		else
		{
			*buffer++ = rand_next() & 0xFF;
			buflen--;
		}
	}
}

void rand_alhastr(uint8_t *buffer, int buflen)
{
	const char alphaset[] = "abcdefghijklmnopqrstuvw012345678";
	
	while(buflen > 0)
	{
		if(buflen >= sizeof(uint32_t))
		{
			int i;
			uint32_t entropy = rand_next();
			
			for(i = 0; i < sizeof(uint32_t); i++)
			{
				uint8_t tmp = entropy & 0xff;
				entropy = entropy >> 8;
				tmp = tmp >> 3;
				*buffer++ = alphaset[tmp];
			}
			buflen -= sizeof(uint32_t);
		}
		else
		{
			*buffer++ = rand_next() % (sizeof(alphaset));
			buflen--;
		}
	}
}
