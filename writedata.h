#ifndef WRITEDATA_H
#define WRITEDATA_H

#include <stdio.h>
#include <openssl/ssl.h>

class write_data
{
public:
    write_data(const char *path);
    bool check_path(const char *path);
    void write_to_server(const char *path, SSL *ssl);
private:
    char *project_path;
};
#endif
