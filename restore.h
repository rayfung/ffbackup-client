#ifndef RESTORE_H
#define RESTORE_H

#include <stdio.h>
#include <vector>
#include <string>
#include <openssl/ssl.h>
#include "helper.h"
using namespace std;

class restore
{
private:
    //file_path: the path of the file to store the informations from the server
    char *file_path;
    vector<string> project_list;
public:
    restore(const char *path);
    void client_get_prj(SSL *ssl);
    void client_get_time_line(SSL *ssl);
    void client_restore(SSL *ssl, const char *project_name, uint32_t number);    
};
#endif
