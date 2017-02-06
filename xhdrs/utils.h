#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>

void util_sleep(int tosleep);

#ifdef DEBUG
void util_msgc(const char *type, const char *fmt, ...);
#endif

void util_strxor(char out[], void *_buf, int len);

char *util_type2str(int type);

#endif /* utils_h */
