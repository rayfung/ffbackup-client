#ifndef SEND_DIFF_H
#define SEND_DIFF_H

#include <stdio.h>
#include "helper.h"
#include <openssl/ssl.h>

class send_diff
{
public:
    send_diff();
    void send_delta(const char *new_file_path, const char *sig_file_path, SSL *ssl);
};
#endif
