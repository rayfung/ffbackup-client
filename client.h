#ifndef CLIENT_H
#define CLIENT_H

#include <openssl/ssl.h>

void start_backup(SSL *ssl);
void get_hash(SSL *ssl);
void get_signature(SSL *ssl);
void send_delta(SSL *ssl);
void send_deletion(SSL *ssl);
void send_addition_fn(SSL *ssl);
void finish_backup(int sock, SSL *ssl);
void die(const char *msg);

#endif
