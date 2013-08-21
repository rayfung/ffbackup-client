#ifndef SEND_ADDITION_H
#define SEND_ADDITION_H

#include <openssl/ssl.h>

class send_addition
{
public:
    send_addition(const char *path);
    void send_to_server(const char *path, SSL *ssl);
private:
    char *project_path;
};
#endif
