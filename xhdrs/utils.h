#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>

#ifdef DEBUG
void util_msgc(const char *type, const char *fmt, ...);
#endif

void util_sleep(int tosleep);

void util_strxor(char out[], void *_buf, int len);

//void util_trim(char *str);

//uint16_t util_crc32(const uint8_t data);

char *util_fdgets(int sockfd, char *buffer, int buflen);

char *util_type2str(int type);

#endif /* utils_h */
