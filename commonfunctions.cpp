#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "commonfunctions.h"
#include "ffbuffer.h"
#include "helper.h"
#include "scan_dir.h"

const char *CFG_PATH = "/etc/ffbackup/client.cfg";

/**
 * read the configuration file
 * cfgFile: the configuration file to read
 * item: the item should be read in the file
 * for example the cfgFile contains:
 * Project = /home/william/Scan
 * Server = localhost
 * the result of the read_item("Project") return "/home/william/Scan"
 */
char *read_item(const char *item)
{
    const size_t MAX_BUFFER_SIZE = 2048;
    FILE *fp;
    char buffer[MAX_BUFFER_SIZE];
    char *dest, *result;
    if((fp = fopen(CFG_PATH, "r") ) == NULL)
    {
        fputs("Can not open the configue file.\n",stderr);
        return NULL;
    }
    while(fgets(buffer, MAX_BUFFER_SIZE, fp) != NULL)
    {
        if(strncmp(item, buffer, strlen(item))==0)
        {
            dest = strstr(buffer, "=") + 2;
            if((result=(char *)malloc(strlen(dest))) == NULL)
            {
                fputs("Malloc error.\n",stderr);
                fclose(fp);
                return NULL;
            }
            size_t length = strlen(dest);
            memcpy(result, dest, length);
            //result = dest;
            result[length - 1] = '\0';
            fclose(fp);
            return (result);
        }
        continue;
    }
    fclose(fp);
    fputs("Can not find the item\n",stderr);
    return NULL;
}


char *read_string(SSL *ssl)
{
    ffbuffer store;
    char buf[1];
    int ret;
    size_t ffbuffer_length = 0;
    char *pass;
    while(1)
    {
        ret = SSL_read(ssl, buf, 1);
        switch( SSL_get_error( ssl, ret ) )
        {
            case SSL_ERROR_NONE:
                break;
            default:
                fputs("SSL_write error.\n",stderr);
                exit(1);
        }
        store.push_back(buf,1);
        if(!buf[0])
            break;
    }
    ffbuffer_length = store.get_size();
    pass = (char *)malloc(ffbuffer_length);
    if(!pass)
    {
        fputs("Malloc error.\n",stderr);
        exit(1);
    }
    store.get(pass, 0, ffbuffer_length);
    return pass;
}


void ssl_read_wrapper(SSL *ssl, void *buffer, int num)
{
    int ret = 0;
    int pos = 0;
    char *ptr = (char *)buffer;
    while(pos < num)
    {
        ret = SSL_read(ssl, ptr + pos, num - pos);    
        switch( SSL_get_error( ssl, ret ) )
        {
            case SSL_ERROR_NONE:
                break;
            default:
                fputs("SSL_read error.\n",stderr);
                exit(1);
        }
        pos += ret;
    }
}


void ssl_write_wrapper(SSL *ssl, const void *buffer, int num)
{
    int ret;
    ret = SSL_write(ssl, buffer, num);
    switch( SSL_get_error( ssl, ret ) )
    {
        case SSL_ERROR_NONE:
            break;
        default:
            fputs("SSL_write error.\n",stderr);
            exit(1);
    }
}

vector<file_info> get_server_list(SSL *ssl)
{
    vector<file_info> file_list;
    uint32_t file_count = 0;
    int i= 0;
    char file_type;
    char *file_path;
    ssl_read_wrapper(ssl, &file_count, 4);
    file_count = ntoh32(file_count);
    for(i = 0; i < (int)file_count; i++)
    {
        file_path = read_string(ssl);
        ssl_read_wrapper(ssl, &file_type, 1);
        file_info store(file_path, file_type);
        file_list.push_back(store);
        free(file_path);
    }
    return file_list;
}

vector<file_info> get_local_list(const char *project_path)
{
    vector<file_info> file_list;
    scan_dir to_scan;
    to_scan.scan_the_dir(project_path, -1);
    file_list = to_scan.get_local_list();
    return file_list;
}

void list_compare(vector<file_info>&local_list,vector<file_info>&server_list, \
        vector<file_info>&addition_list, vector<file_info>&diff_list, vector<file_info>&deletion_list)
{
    size_t i = 0;
    size_t j = 0;
    vector<file_info> temp_list = server_list;
    bool found;

    while(i < local_list.size())
    {
        found = false;
        while(j < temp_list.size())
        {
            if(strcmp(local_list.at(i).get_path(), temp_list.at(j).get_path()) == 0)
            {
                if(local_list.at(i).get_file_type() == temp_list.at(j).get_file_type())
                {
                    if(local_list.at(i).get_file_type() == 'd')
                        temp_list.erase(temp_list.begin() + j);
                    else
                    {
                        diff_list.push_back(local_list.at(i));
                        temp_list.erase(temp_list.begin() + j);
                    }
                    found = true;
                    break;
                }
            }
            j++;
        }
        if(!found)
            addition_list.push_back(local_list.at(i));
        i++;
        j = 0;
    }
    deletion_list = temp_list;
}

void simplify_deletion_list(vector<file_info>&deletion_list)
{
    vector<file_info> temp_list = deletion_list;
    const size_t max_buffer_size = 1024;
    char buffer[max_buffer_size];
    size_t buffer_length = 0;
    size_t i = 0;
    size_t j = 0;
    while(i < temp_list.size())
    {
        if(temp_list.at(i).get_file_type() == 'd')
        {
            strcpy(buffer, temp_list.at(i).get_path());
            buffer_length = strlen(buffer);
            strcpy(&buffer[buffer_length],"/");
            buffer_length++;
            j = 0;
            while( j < deletion_list.size())
            {
                if(strncmp(buffer, deletion_list.at(j).get_path(), buffer_length) == 0)
                {
                    deletion_list.erase(deletion_list.begin() + j);
                }
                else
                    j++;
            }
        }
        i++;
    }
}

void find_delta_list(vector<file_info> diff_list, vector<file_info>&delta_list)
{
    const size_t md_length = 20;
    unsigned char *sha;
    unsigned char temp[md_length];
    unsigned int i = 0;
    unsigned int j = 0;
    sha = (unsigned char *)malloc(sizeof(unsigned char) * 20);
    if(!sha)
    {
        fputs("Malloc error.\n",stderr);
        exit(1);
    }
    for(i = 0; i < diff_list.size(); i++)
    {
        sha = diff_list.at(i).get_sha1();
        get_file_sha1(diff_list.at(i).get_path(), temp);
        for(j = 0; j < md_length; j++)
        {
            if(temp[j] == sha[j]) continue;
            else break;
        }
        if(j < 20)
            delta_list.push_back(diff_list.at(i));
        j = 0;
    }
}

void get_file_sha1(const char* path, unsigned char *md)
{
    char *project_path = read_item("Path");
    if(!project_path)
    {
        fputs("Read_item error.\n",stderr);
        exit(1);
    }
    if(chdir(project_path) == -1)
    {
        fputs("Chdir error.\n",stderr);
        exit(1);
    }

    int pf = open(path,O_RDONLY);
    if(pf == -1)
    {
        fputs("File can not be open.\n",stderr);
        exit(1);
    }
    if(chdir("..") == -1)
    {
        fputs("Chdir error.\n",stderr);
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

