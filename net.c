#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "xhdrs/includes.h"
#include "xhdrs/net.h"
#include "xhdrs/packet.h"
#include "xhdrs/sha256.h"
#include "xhdrs/utils.h"

ipv4_t net_local_addr(void)
{
	int err, val = 1, sockfd = -1;
	
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	struct timeval tv;
	
	struct sockaddr in_addr;
	socklen_t in_len = sizeof(in_addr);
	
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;     	// Return IPv4 and IPv6 choices
	hints.ai_socktype = SOCK_DGRAM;		// We want a UDP socket
	hints.ai_flags = AI_PASSIVE;		// All interfaces
	
	err = getaddrinfo("8.8.8.8", "53", &hints, &result);
	if(err < 0)
	{
		util_msgc("Error", "Failed to Getaddrinfo!");
		return -1;
	}
	
	for(rp = result; rp != NULL; rp = rp->ai_next)
	{
		sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if(sockfd < 0)
			continue;
		
		if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(int)) < 0)
		{
			util_msgc("Warning", "Unable to set SO_REUSEADDR: %s",  
				strerror(errno));
		}
		
		tv.tv_sec = 5;
		tv.tv_usec = 0;
		
		if(setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, 
						(struct timeval*)&tv, sizeof(struct timeval)))
		{
			util_msgc("Warning", "Unable to set SO_RCVTIMEO: %s",  
				strerror(errno));
		}
		
		if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, 
						(struct timeval*)&tv, sizeof(struct timeval)))
		{
			util_msgc("Warning", "Unable to set SO_RCVTIMEO: %s",  
				strerror(errno));
		}
		
		if((err = connect(sockfd, rp->ai_addr, rp->ai_addrlen)) < 0)
		{
			close(sockfd);
			sockfd = -1;
		}
		
		if(err == 0)
			break;
		//close(sockfd);
	}
	
	freeaddrinfo(result);
	
	if(sockfd < 0)
	{
		util_msgc("Error", "Failed to connect: %s", strerror(errno));
		return -1;
	}
	
	if(net_set_nonblocking(sockfd) < 0)
	{
		util_msgc("Error", "Failed to make socket nonblocking: %s", 
			strerror(errno));
		return -1;
	}
	
	getsockname(sockfd, &in_addr, &in_len);
	
	close(sockfd);
	
	return ((struct sockaddr_in*)&in_addr)->sin_addr.s_addr;
}

int net_fdsend(int sockfd, int type, char *buffer)
{
	struct Packet pkt;
	
	memset(&pkt, 0, sizeof(pkt));
	
	pkt.type = type;
	pkt.timestamp = time(NULL);
	
	strcpy(pkt.msg.payload, buffer);
	pkt.msg.length = strlen(pkt.msg.payload);
	sha256(pkt.msg.payload, pkt.msg.sha256);
	
	util_strxor(pkt.msg.payload, pkt.msg.payload, pkt.msg.length);
	
	if(send(sockfd, &pkt, sizeof(pkt), MSG_NOSIGNAL) < 0)
	{
		util_msgc("Error", "Unable to send Packet!");
		return 1;
	}
	
	return 0;
}

int net_set_nonblocking(int sockfd)
{
    int rc, nonblocking = 1;

    rc = fcntl(sockfd, F_GETFL, 0);
    if(rc < 0)
        return -1;

    rc = fcntl(sockfd, F_SETFL, nonblocking ? 
								(rc | O_NONBLOCK) : 
								(rc & ~O_NONBLOCK));
    if(rc < 0)
        return -1;

    return 0;
}

int net_bind(const char *portno, int protocol)
{
	int err, val = 1, sockfd = -1;
	
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;     		// Return IPv4 and IPv6 choices
	if(protocol == IPPROTO_TCP)
		hints.ai_socktype = SOCK_STREAM;	// We want a TCP socket
	else if(protocol == IPPROTO_UDP)
		hints.ai_socktype = SOCK_DGRAM;		// We want a UDP socket
	else return -1;
	hints.ai_flags = AI_PASSIVE;			// All interfaces
	
	err = getaddrinfo(NULL, portno, &hints, &result);
	if(err < 0)
	{
		util_msgc("Error", "Failed to Getaddrinfo!");
		return -1;
	}
	
	for(rp = result; rp != NULL; rp = rp->ai_next)
	{
		sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if(sockfd < 0)
			continue;
		
		if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(int)) < 0)
		{
			util_msgc("Warning", "Unable to set SO_REUSEADDR: %s",  
				strerror(errno));
		}
		
		err = bind(sockfd, rp->ai_addr, rp->ai_addrlen);
		if(err == 0)
			break;
		//close(sockfd);
	}
	
	freeaddrinfo(result);
	
	if(rp == NULL)
	{
		util_msgc("Error", "Could not bind!");
		return -1;
	}
	
	return sockfd;
}

int net_connect(const char *addr, const char *portno, int protocol)
{
	int err, val = 1, sockfd = -1;
	
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	struct timeval tv;
	
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;     		// Return IPv4 and IPv6 choices
	if(protocol == IPPROTO_TCP)
		hints.ai_socktype = SOCK_STREAM;	// We want a TCP socket
	else if(protocol == IPPROTO_UDP)
		hints.ai_socktype = SOCK_DGRAM;		// We want a UDP socket
	else return -1;
	hints.ai_flags = AI_PASSIVE;			// All interfaces
	
	err = getaddrinfo(addr, portno, &hints, &result);
	if(err < 0)
	{
		util_msgc("Error", "Failed to Getaddrinfo!");
		return -1;
	}
	
	for(rp = result; rp != NULL; rp = rp->ai_next)
	{
		sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if(sockfd < 0)
			continue;
		
		if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(int)) < 0)
		{
			util_msgc("Warning", "Unable to set SO_REUSEADDR: %s",  
				strerror(errno));
		}
		
		tv.tv_sec = 5;
		tv.tv_usec = 0;
		
		if(setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, 
						(struct timeval*)&tv, sizeof(struct timeval)))
		{
			util_msgc("Warning", "Unable to set SO_RCVTIMEO: %s",  
				strerror(errno));
		}
		
		if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, 
						(struct timeval*)&tv, sizeof(struct timeval)))
		{
			util_msgc("Warning", "Unable to set SO_RCVTIMEO: %s",  
				strerror(errno));
		}
		
		if((err = connect(sockfd, rp->ai_addr, rp->ai_addrlen)) < 0)
		{
			close(sockfd);
			sockfd = -1;
		}
		
		if(err == 0)
			break;
		//close(sockfd);
	}
	
	freeaddrinfo(result);
	
	if(sockfd < 0)
	{
		util_msgc("Error", (protocol == IPPROTO_TCP)?
			"Failed to connect: %s":
			"Failed to sendto: %s", 
			strerror(errno));
		return -1;
	}
	
	if(net_set_nonblocking(sockfd) < 0)
	{
		util_msgc("Error", "Failed to make socket nonblocking: %s", 
			strerror(errno));
		return -1;
	}
	
	util_msgc("Info", "Connected to [%s:%s]", addr, portno);
	
	return sockfd;
}
