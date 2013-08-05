#include "sendinfo.h"
#include "commonfunctions.h"
#include "ffbuffer.h"
#include <string>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/err.h>

using namespace std;

send_info::send_info(const char *path, char file_type, unsigned char *md)
{
    int i;
    size_t length = strlen(path);
    this->path = (char *) malloc( sizeof(char) * (length + 1) );
    strcpy(this->path, path);
    this->file_type = file_type;
    if(file_type == 'f')
    {
        for(i = 0; i < SHA_DIGEST_LENGTH; i++)
        {
            this->md[i] = md[i];
        }
    }
}

char* send_info::get_path()
{
    return this->path;
}

char send_info::get_file_type()
{
    return this->file_type;
}

unsigned char* send_info::get_md()
{
    return this->md;
}

scan_dir::scan_dir(const char *dir_path)
{
    size_t length;
    this->file_count = 0;
    length = strlen(dir_path);
    if(!length)
    {
        this->dir_path = (char *)malloc(sizeof(char) * 2);
        this->dir_path[0] = '.';
        this->dir_path[1] = '\0';
    }
    else
    {
        this->dir_path = (char *)malloc(sizeof(char) * (length + 1));
        strcpy(this->dir_path, dir_path);
    }
}

void scan_dir::sha1(const char* path, unsigned char *md)
{
    int pf = open(path,O_RDONLY);
    if(pf == -1)
    {
        fputs("File can not be open.\n",stderr);
        exit(1);
    }
    const size_t buffer_size = 2048;
    ssize_t ret;
    unsigned char data[buffer_size];
    SHA_CTX ctx;
    if(SHA1_Init(&ctx) == 0)
    {
        fputs("SHA1_Init error.\n",stderr);
        exit(1);
    }
    while( (ret = read(pf, data, buffer_size)) > 0)
    {
        if(SHA1_Update(&ctx,data,ret) == 0)
        {
            fputs("SHA1_Update error.\n",stderr);
            exit(1);
        }
    }
    if(SHA1_Final(md, &ctx) == 0)
    {
        fputs("SHA1_Final error.\n",stderr);
        exit(1);
    }
    return ;   
}

void scan_dir::scan_the_dir(const char *dir, int parent_index)
{
    DIR *dp;
    struct dirent *entry;
    struct stat statbuf;
    unsigned char md[SHA_DIGEST_LENGTH];
    if((dp = opendir(dir)) == NULL || chdir(dir) < 0)
    {
        if(parent_index == -1)
            fputs("Can not scan the director.\n",stderr);
        return ;
    }
    while((entry = readdir(dp)) != NULL)
    {
        lstat(entry->d_name, &statbuf);
        if(S_ISDIR(statbuf.st_mode))
        {
            if(strcmp(".",entry->d_name) == 0 || strcmp("..",entry->d_name) == 0)
                continue;
            memset(md, 0, sizeof(md));
            string name;
            if(parent_index != -1)
            {
                name = send_list.at(parent_index).get_path();
                name += "/";
            }
            name += entry->d_name;
            send_info to_store(entry->d_name,'d',md);
            send_list.push_back(to_store);
            file_count++;
            scan_the_dir(entry->d_name, send_list.size() - 1);
        }
        else
        {
            sha1(entry->d_name,md);
            string name;
            if(parent_index != -1)
            {
                name = send_list.at(parent_index).get_path();
                name += "/";
            }
            name += entry->d_name;
            send_info to_store(entry->d_name,'f',md);
            send_list.push_back(to_store);
            file_count++;
        }
    }
    chdir("..");
    closedir(dp);
}

uint32_t scan_dir::get_file_count()
{
	return file_count;
}

void scan_dir::send_file_list(SSL *ssl)
{
    char *send_buffer;
    ffbuffer buffer_to_send;
    size_t send_buffer_length = 0;
    size_t get_result = 0;
    uint32_t count = file_count;
    int i;
    char version = 1;
    char command = 0x01;
    char *project_path = read_item(dir_path,"Path");
    char *project_name = read_item(dir_path,"Project");
    scan_the_dir(project_path, -1);

    count = hton32(count);
    buffer_to_send.push_back(&version,1);
    buffer_to_send.push_back(&command,1);
    buffer_to_send.push_back(project_name,strlen(project_name));
    buffer_to_send.push_back("\0",1);
    buffer_to_send.push_back(&count,4);

    send_buffer_length = buffer_to_send.get_size();
    send_buffer = (char *)malloc(send_buffer_length * sizeof(char));
    get_result = buffer_to_send.get(send_buffer, 0, send_buffer_length);
    if(get_result != send_buffer_length)
    {
        fputs("ffbuffer get error.\n",stderr);
        exit(1);
    }
    SSL_write(ssl, send_buffer, get_result);
    buffer_to_send.clear();
    free(send_buffer);
    for(i = 0; i < (int)file_count; i++)
    {
        SSL_write(ssl,send_list.at(i).get_path(),(strlen(send_list.at(i).get_path()) + 1));
        if(send_list.at(i).get_file_type() == 'f')
        {
            SSL_write(ssl,"f",1);
            SSL_write(ssl,send_list.at(i).get_md(),SHA_DIGEST_LENGTH);
        }
        else
            SSL_write(ssl,"d",1);
    }
	/*
    char buf[2];
    SSL_read(ssl,buf,2);
	*/
}
