#include "send_addition.h"
#include "helper.h"
#include "commonfunctions.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/err.h>

send_addition::send_addition(const char *path)
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

void send_addition::send_to_server(const char*path, SSL *ssl)
{
    if(chdir(project_path) == -1)
    {
        fputs("Project path is wrong.\n",stderr);
        exit(1);
    }
    const size_t max_buffer_size = 1024;
    FILE *pf;
    struct stat file_info;
    uint64_t file_size;
    char buffer[max_buffer_size];
    size_t result= 0;
    if(stat(path,&file_info) == -1)
    {
        fputs("Stat error.\n",stderr);
        exit(1);
    }
    if(S_ISDIR(file_info.st_mode))
    {
        ssl_write_wrapper(ssl, path, strlen(path) + 1);
        ssl_write_wrapper(ssl, "d", 1);
    }
    if(S_ISREG(file_info.st_mode))
    {
        file_size = (uint64_t)file_info.st_size;
        pf = fopen(path, "rb");
        if(!pf)
        {
            fputs("File cannot be open.\n",stderr);
            exit(1);
        }
        file_size = hton64(file_size);
        ssl_write_wrapper(ssl, path, strlen(path) + 1);
        ssl_write_wrapper(ssl, "f", 1);
        ssl_write_wrapper(ssl, &file_size, 8);
        while(!feof(pf))
        {
            result = fread(buffer, 1, max_buffer_size, pf);
            if(result > 0)
                ssl_write_wrapper(ssl, buffer, result);
        }
        fclose(pf);
    }
    if(chdir("..") == -1)
    {
        fputs("Chdir error.\n",stderr);
        exit(1);
    }
    return ;
}
