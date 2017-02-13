#ifndef CHECKSUM_H
#define CHECKSUM_H

uint16_t checksum_generic(uint16_t *, uint32_t);
uint16_t checksum_tcpudp(struct iphdr *, void *, uint16_t, int);

#endif /* checksum_h */
