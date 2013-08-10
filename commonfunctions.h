#ifndef COMMONFUNCTIONS_H
#define COMMONFUNCTIONS_H

#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
char *read_item(char const *cfgFile, char const *item);
char *read_string(SSL *ssl);
void ssl_read_wrapper(SSL *ssl, void *buffer, int num);
void ssl_write_wrapper(SSL *ssl, const void *buffer, int num); 
#endif
