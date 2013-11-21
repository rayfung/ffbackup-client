#ifndef HELPER_H
#define HELPER_H

#include <vector>
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdint.h>
#include "file_info.h"

using namespace std;

void dump_data(void *data, size_t size);

uint16_t ntoh16(uint16_t net);

uint16_t hton16(uint16_t host);

uint32_t ntoh32(uint32_t net);

uint32_t hton32(uint32_t host);

uint64_t ntoh64(uint64_t net);

uint64_t hton64(uint64_t host);

char *read_string(SSL *ssl);
void ssl_read_wrapper(SSL *ssl, void *buffer, int num);
void ssl_write_wrapper(SSL *ssl, const void *buffer, int num);
vector<file_info> get_server_list(SSL *ssl);
vector<file_info> get_local_list(const char *project_path);
void find_delta_list(vector<file_info> diff_list, vector<file_info>&delta_list);
void get_file_sha1(const char *file, unsigned char *md);
void list_compare(vector<file_info>&local_list,vector<file_info>&sever_list,
                  vector<file_info>&addition_list, vector<file_info>&diff_list,
                  vector<file_info>&deletion_list);
void simplify_deletion_list(vector<file_info>&deletion_list);
void send_file_delta(const char* new_file_path, const char *sig_file_path, SSL *ssl);
void send_file_addition(const char *path, SSL *ssl);

#endif
