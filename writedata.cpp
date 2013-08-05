#include "writedata.h"
#include "helper.h"
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/err.h>


write_data::write_data(const char *path)
{
    size_t length = strlen(path);
    if(length)
    {
        this->project_path = (char *)malloc(sizeof(char) * (length + 1));
        strcpy(this->project_path, path);
    }
    else
    {
        fputs("project is NULL.\n",stderr);
        exit(1);
    }
}

bool write_data::check_path(const char *path)
{
    struct stat info;
    stat(path, &info);
    if(!S_ISREG(info.st_mode))
    {
        fputs("The file is not a regular file.\n", stderr);
        return false;
    }
    else
        return true;
}

void write_data::write_to_server(const char*path, SSL *ssl)
{
    if(chdir(project_path) == -1)
    {
        fputs("Project path is wrong.\n",stderr);
        exit(1);
    }
	uint64_t file_size;
	struct stat file_info;
	const size_t MAX_BUFFER_SIZE = 1024;
	char version = 1;
	char command = 0x00;
    FILE *pf;
	if(stat(path,&file_info) == -1)
	{
		char error_code[2]; 
		command = 0x01;
		error_code[0] = version;
		error_code[1] = command;
		SSL_write(ssl, error_code, 2);		
	}
	if(!S_ISREG(file_info.st_mode))
	{
		char error_code[2];
		command = 0x02;
		error_code[0] = version;
		error_code[1] = command;
		SSL_write(ssl, error_code, 2);
	}
	file_size = (uint64_t)file_info.st_size;
	printf("File's size:%d\n",file_size);
    file_size = hton64(file_size);
    pf = fopen(path, "r");
    if(!pf)
    {
        fputs("File can not be open.\n", stderr);
        exit(1);
    }
    char buffer[MAX_BUFFER_SIZE];
    size_t result;
    size_t total_count = 0;
    int write_length;
    buffer[0] = version;
    buffer[1] = command;
    memcpy(&buffer[2],&file_size,8);
    SSL_write(ssl, buffer, 10);
    memset(buffer, 0, MAX_BUFFER_SIZE);
    while(!feof(pf))
    {
        result = fread(buffer, 1, MAX_BUFFER_SIZE, pf);
        if((result != MAX_BUFFER_SIZE ) && !feof(pf))
        {
            fputs("Reading error.\n", stderr);
            exit(1);
        }
        write_length = SSL_write(ssl, buffer, result);
        if(write_length > 0 && write_length != (int)result)
        {
            total_count += write_length;
            fseek(pf, total_count, SEEK_SET);
        }
        else if(write_length <= 0)
        {
            fputs("SSL_write error.\n",stderr);
            exit(1);
        }
        else
            total_count += write_length;
    }
    fclose(pf);
    if(chdir("..") == -1)
    {
        fputs("Chdir error.\n",stderr);
        exit(1);
    }
    return ;
}
