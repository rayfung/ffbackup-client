#include "send_diff.h"
#include "ffbuffer.h"
#include "commonfunctions.h"
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <librsync.h>

send_diff::send_diff()
{
}

void send_diff::send_delta(const char* new_file_path, const char *sig_file_path, SSL *ssl)
{
    ffbuffer store;
    FILE *sig_file;
    FILE *new_file;
    FILE *delta_file;
    size_t result = 0;
    const size_t max_buffer_size = 1024;
    char delta_buffer[max_buffer_size];
    long lsize = 0;
    uint64_t delta_length = 0;
    rs_result ret;
    rs_signature_t *sumset;
    rs_stats_t stats;

    sig_file = fopen(sig_file_path,"rb"); 
    new_file = fopen(new_file_path,"rb");
    delta_file = tmpfile();

    ret = rs_loadsig_file(sig_file, &sumset, &stats);
    if(ret != RS_DONE)
    {
        puts(rs_strerror(ret));
        exit(1);
    }
    rs_log_stats(&stats);
    if(rs_build_hash_table(sumset) != RS_DONE)
    {
        puts(rs_strerror(ret));
        exit(1);
    }
    if(rs_delta_file(sumset, new_file, delta_file, &stats) != RS_DONE)
    {
        puts(rs_strerror(ret));
        exit(1);
    }
    fseek (delta_file , 0 , SEEK_END);
    lsize = ftell(delta_file);      
    if(lsize < 0)
    {
        fputs("Delta_file is wrong.\n",stderr);
        exit(1);
    }

    rewind(delta_file);
    delta_length = (uint64_t)lsize;
    delta_length = hton64(delta_length);

    ssl_write_wrapper(ssl, new_file_path, strlen(new_file_path) + 1);
    ssl_write_wrapper(ssl, &delta_length, 8);
    
    while(!feof(delta_file))
    {
        result = fread(delta_buffer, 1, max_buffer_size, delta_file);
        ssl_write_wrapper(ssl, delta_buffer, result);
    }

    rs_log_stats(&stats);
    rs_free_sumset(sumset);
    fclose(sig_file);
    fclose(new_file);
    fclose(delta_file);
    return ;
}

