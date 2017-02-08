#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>

#ifdef DEBUG
void util_msgc(const char *type, const char *fmt, ...);
#endif

void util_sleep(int tosleep);

void util_strxor(char out[], void *_buf, int len);

char *util_type2str(int type);

#endif /* utils_h */
