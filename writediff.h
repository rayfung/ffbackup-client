#ifndef WRITEDIFF_H
#define WRITEDIFF_H

#include <stdio.h>
#include "helper.h"
#include <openssl/ssl.h>

class write_diff
{
public:
    write_diff(const char *path);
    void calculate_delta(const char *new_file_path, SSL *ssl);
    void write_to_server(SSL *ssl);
private:
    char *project_path;
};
#endif
