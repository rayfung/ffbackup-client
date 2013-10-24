#ifndef COMMONFUNCTIONS_H
#define COMMONFUNCTIONS_H

#include "file_info.h"
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <vector>

using namespace std;

char *read_item(const char *item);
char *read_string(SSL *ssl);
void ssl_read_wrapper(SSL *ssl, void *buffer, int num);
void ssl_write_wrapper(SSL *ssl, const void *buffer, int num); 
vector<file_info> get_server_list(SSL *ssl);
vector<file_info> get_local_list(const char *project_path);
void find_delta_list(vector<file_info> diff_list, vector<file_info>&delta_list);
void get_file_sha1(const char *file, unsigned char *md);
void list_compare(vector<file_info>&local_list,vector<file_info>&sever_list,
        vector<file_info>&addition_list, vector<file_info>&diff_list, vector<file_info>&deletion_list);
void simplify_deletion_list(vector<file_info>&deletion_list);
#endif
