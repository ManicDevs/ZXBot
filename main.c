#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/time.h>
#include <netinet/in.h>

#include "xhdrs/includes.h"
#include "xhdrs/net.h"
#include "xhdrs/packet.h"
#include "xhdrs/sha256.h"
#include "xhdrs/utils.h"

time_t proc_startup;
sig_atomic_t exiting = 0;

uint32_t table_key = 0xdeadbeef; // util_strxor; For packets only?

static volatile int sockfd = -1;
static char uniq_id[32] = "";

static void init_exit(void)
{	
	util_msgc("Info", "Process ran for %ld second(s).", 
		(time(NULL) - proc_startup));
	util_msgc("Info", "Exiting: now");
}

static void sigexit(int signo)
{
    exiting = 1;
	init_exit();
}

static void init_signals(void)
{
    struct sigaction sa;
    sigset_t ss;
	
    sigemptyset(&ss);
	
    sa.sa_handler = sigexit;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, 0);
	
#ifdef DEBUG
	util_msgc("Info", "Initiated Signals!");
#endif
}

static void init_uniq_id(void)
{
	int fd, rc, offset;
	char tmp_uniqid[21], final_uniqid[41];
	
	fd = open("/dev/urandom", O_RDONLY);
	if(fd < 0)
	{
#ifdef DEBUG
		util_msgc("Error", "open(urandom)");
#endif
		_exit(1);
	}
	
	rc = read(fd, tmp_uniqid, 20);
	if(rc < 0)
	{
#ifdef DEBUG
		util_msgc("Error", "read(urandom)");
#endif
		_exit(1);
	}
		
	close(fd);
	
	for(offset = 0; offset < 20; offset++)
	{
		sprintf((final_uniqid + (2 * offset)), 
				"%02x", tmp_uniqid[offset] & 0xff);
	}
	
	sprintf(uniq_id, "%s", final_uniqid);
	util_msgc("Info", "Your Machine ID is %s", uniq_id);
	
    {
        unsigned seed;
        read(fd, &seed, sizeof(seed));
        srandom(seed);
    }
}

int main(int argc, char *argv[])
{
	proc_startup = time(NULL);
	init_signals();
	init_uniq_id();
	
	while((sockfd = net_connect("localhost", "3448", IPPROTO_TCP)) <= 0)
	{
		if(exiting)
			break;
#ifdef DEBUG
		util_msgc("Info", "Unable to connect, retrying...");
#endif
		util_sleep(1);
	}
	
	while(!exiting)
	{
		ssize_t buflen;
		char pktbuf[512];
		
		struct Packet pkt;
		
		memset(pktbuf, 0, sizeof(pktbuf));
		
		while(memset(pktbuf, 0, sizeof(pktbuf)) && 
			(buflen = recv(sockfd, pktbuf, sizeof(pktbuf), 0)))
		{
			if(exiting)
				break;
			
			if(buflen != sizeof(struct Packet))
				continue;
			
			memcpy(&pkt, pktbuf, buflen);
			
#ifdef DEBUG
			// Packet received
			util_msgc("Info", "We've received a %s!", util_type2str(pkt.type));
#endif
			
			switch(pkt.type)
			{
				case PING:
					net_fdsend(sockfd, PONG, "");
				break;
			}
		} // While
	} // While
	
	close(sockfd);
	
	return EXIT_SUCCESS;
}
