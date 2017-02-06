#ifndef NET_H
#define NET_H

int net_fdsend(int sockfd, int type, char *buffer);

int net_set_nonblocking(int sockfd);

int net_bind(const char *port, int protocol);

int net_connect(const char *addr, const char *port, int protocol);

#endif /* net_h */
