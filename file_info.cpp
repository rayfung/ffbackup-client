#include "file_info.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

file_info::file_info(const char *path, char file_type)
{
    size_t length = strlen(path);
    this->path = (char *) malloc( sizeof(char) * (length + 1) );
    strcpy(this->path, path);
    this->file_type = file_type;
}

char* file_info::get_path()
{
    return this->path;
}

char file_info::get_file_type()
{
    return this->file_type;
}

char *file_info::get_sig_path()
{
    return sig_path;
}

void file_info::set_sig_path(const char *str)
{
    size_t length = strlen(str);
    if(length)
    {
        sig_path = (char *)malloc( sizeof(char) * (length + 1));
        if(!sig_path)
        {
            fputs("Malloc error.\n",stderr);
            exit(1);
        }
        strcpy(sig_path, str);
    }
    else
    {
        fputs("Delta file path is NULL.\n",stderr);
        exit(1);
    }
}

void file_info::set_sha1(char *str)
{
    int i = 0;
    for(i = 0; i < 20; i++)
    {
        sha1[i] = str[i];
    }
}
