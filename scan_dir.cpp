#include "scan_dir.h"
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


scan_dir::scan_dir(const char *dir_path)
{
    size_t length;
    length = strlen(dir_path);
    if(!length)
    {
        fputs("Dir_path is NULL.\n",stderr);
        exit(1);
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

//scan the local project director
void scan_dir::scan_the_dir(const char *dir, int parent_index)
{
    DIR *dp;
    struct dirent *entry;
    struct stat statbuf;
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
            string name;
            if(parent_index != -1)
            {
                name = local_list.at(parent_index).get_path();
                name += "/";
            }
            name += entry->d_name;
            file_info to_store(name.c_str(),'d');
            local_list.push_back(to_store);
            scan_the_dir(entry->d_name, local_list.size() - 1);
        }
        else if(S_ISREG(statbuf.st_mode))
        {
           
            string name;
            if(parent_index != -1)
            {
                name = local_list.at(parent_index).get_path();
                name += "/";
            }
            name += entry->d_name;
            file_info to_store(name.c_str(),'f');
            local_list.push_back(to_store);
        }
    }
    if(chdir("..") == -1)
    {
		fputs("Chdir error.\n",stderr);
		exit(1);
    }
    closedir(dp);
}

vector<file_info> scan_dir::get_local_list()
{
    return local_list;
}
