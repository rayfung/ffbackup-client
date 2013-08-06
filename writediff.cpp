#include "writediff.h"
#include "ffbuffer.h"
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <librsync.h>

write_diff::write_diff(const char*path)
{
    size_t length = strlen(path);
    if(length)
    {
        project_path = (char *)malloc(sizeof(char) * (length + 1));
        strcpy(project_path, path);
    }
    else
    {
        fputs("The project's path is NULL.\n",stderr);
        exit(1);
    }
}

void write_diff::calculate_delta(const char* new_file_path, SSL *ssl)
{
	//length: the length of the sig_buffer
	uint64_t length;
	//total_read: the read count from the server
	uint64_t total_read = 0;
	const size_t MAX_BUFFER_SIZE = 1024;
	uint64_t delta_length;
	char read_buffer[MAX_BUFFER_SIZE];
	char delta_buffer[MAX_BUFFER_SIZE];
    int ssl_ret;
	//lsize: use to tell the file's size
	long lsize;
	//result: the read count of each delta_file's read
	size_t result;
	//to_send: the first 10 command to send to the server
	char to_send[10];

	ffbuffer store;
	FILE *sig_file;
	FILE *new_file;
	FILE *delta_file;
	rs_result ret;
	rs_signature_t *sumset;
	rs_stats_t stats;

    sig_file = tmpfile();
	new_file = fopen(new_file_path,"rb");
    delta_file = tmpfile();

	ssl_ret = SSL_read(ssl,&length,8);

    switch( SSL_get_error( ssl, ssl_ret ) )
    {
        case SSL_ERROR_NONE:
            break;
        default:
            fputs("SSL_read error.\n",stderr);
            exit(1);
    }
	length = ntoh64(length);
	
	while((length - total_read) >= MAX_BUFFER_SIZE)
	{
	    ssl_ret = SSL_read(ssl,read_buffer,MAX_BUFFER_SIZE);
        switch( SSL_get_error( ssl, ssl_ret ) )
        {
            case SSL_ERROR_NONE:
                break;
            default:
                fputs("SSL_read error.\n",stderr);
                exit(1);
        }
		total_read += MAX_BUFFER_SIZE;
		fwrite(read_buffer, 1, MAX_BUFFER_SIZE, sig_file);
	}
    if(total_read != length)
    {
	    ssl_ret = SSL_read(ssl,read_buffer,length - MAX_BUFFER_SIZE);
        switch( SSL_get_error( ssl, ssl_ret ) )
        {
            case SSL_ERROR_NONE:
                break;
            default:
                fputs("SSL_read error.\n",stderr);
                exit(1);
        }
        fwrite(read_buffer, 1, length - MAX_BUFFER_SIZE, sig_file);
    }

    fflush(sig_file);
    rewind(sig_file);
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
		fputs("delta_file is wrong.\n",stderr);
		exit(1);
	}
  	rewind(delta_file);
    
	delta_length = (uint64_t)lsize;
	delta_length = hton64(delta_length);
	to_send[0] = 1;
	to_send[1] = 0x00;
	memcpy(&to_send[2],&delta_length,8);
	ssl_ret = SSL_write(ssl, to_send, 10);
    switch( SSL_get_error( ssl, ssl_ret ) )
    {
        case SSL_ERROR_NONE:
            break;
        default:
            fputs("SSL_write error.\n",stderr);
            exit(1);
    }
	while(!feof(delta_file))
	{
		result = fread(delta_buffer, 1, MAX_BUFFER_SIZE, delta_file);
		ssl_ret = SSL_write(ssl, delta_buffer, result);
        switch( SSL_get_error( ssl, ssl_ret ) )
        {
            case SSL_ERROR_NONE:
                break;
            default:
                fputs("SSL_write error.\n",stderr);
                exit(1);
        }
	}

	rs_log_stats(&stats);
	rs_free_sumset(sumset);
	fclose(sig_file);
	fclose(new_file);
	fclose(delta_file);
    return ;
}

void write_diff::write_to_server(SSL *ssl)
{
	char *path;
	char buf[1];
	ffbuffer store;
	size_t ffbuffer_length = 0;
    int ret;
	while(1)
	{
		ret = SSL_read(ssl, buf, 1);
        switch( SSL_get_error( ssl, ret ) )
        {
            case SSL_ERROR_NONE:
                break;
            default:
                fputs("SSL_read error.\n",stderr);
                exit(1);
        }
		store.push_back(buf, 1);
		if(!buf[0])
			break;
	}
	ffbuffer_length = store.get_size();
	path = (char *)malloc(ffbuffer_length);
	store.get(path, 0, ffbuffer_length);
    if(chdir(project_path) == -1)
    {
        fputs("Project path is wrong.\n",stderr);
        exit(1);
    }
	struct stat file_info;
	char version = 1;
	char command = 0x00;
	if(stat(path,&file_info) == -1)
	{
		char error_code[2]; 
		command = 0x01;
		error_code[0] = version;
		error_code[1] = command;
		ret = SSL_write(ssl, error_code, 2);	
        switch( SSL_get_error( ssl, ret ) )
        {
            case SSL_ERROR_NONE:
                break;
            default:
                fputs("SSL_write error.\n",stderr);
                exit(1);
        }
        free(path);
		return ;	
	}
	if(!S_ISREG(file_info.st_mode))
	{
		char error_code[2];
		command = 0x02;
		error_code[0] = version;
		error_code[1] = command;
		ret = SSL_write(ssl, error_code, 2);
        switch( SSL_get_error( ssl, ret ) )
        {
            case SSL_ERROR_NONE:
                break;
            default:
                fputs("SSL_write error.\n",stderr);
                exit(1);
        }
        free(path);
		return ;
	}
	calculate_delta(path,ssl);
    free(path);
	if(chdir("..") == -1)
    {
        fputs("Chdir error.\n",stderr);
        exit(1);
    }
}
