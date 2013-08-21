#ifndef GET_SIG_H
#define GET_SIG_H

#include "file_info.h"
#include <openssl/ssl.h>
#include <vector>

using namespace std;

class get_sig
{
public:
    get_sig();
    void set_from_server(vector<file_info> &file_list, SSL *ssl);
};

#endif
