#include <stdlib.h>
#include <string.h>
#include "commonfunctions.h"
#include "ffbuffer.h"
#include "helper.h"
#include "scan_dir.h"

/**
 * read the configuration file
 * cfgFile: the configuration file to read
 * item: the item should be read in the file
 * for example the cfgFile contains:
 * Project = /home/william/Scan
 * Server = localhost
 * the result of the read_item(cfgFile, "Project") return "/home/william/Scan"
 */
char *read_item(char const *cfgFile, char const *item)
{
    const size_t MAX_BUFFER_SIZE = 2048;
    FILE *fp;
    char buffer[MAX_BUFFER_SIZE];
    char *dest, *result;
    if((fp = fopen(cfgFile, "r") ) == NULL)
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
    int ret;
    ret = SSL_read(ssl, buffer, num);
    switch( SSL_get_error( ssl, ret ) )
    {
        case SSL_ERROR_NONE:
            break;
        default:
            fputs("SSL_read error.\n",stderr);
            exit(1);
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
    scan_dir to_scan(project_path);
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
    while(i < local_list.size())
    {
        while(j < server_list.size())
        {
            if(strcmp(local_list.at(i).get_path(), server_list.at(j).get_path()) == 0)
            {
                if(local_list.at(i).get_file_type() == server_list.at(j).get_file_type())
                {
                    diff_list.push_back(local_list.at(i));
                    temp_list.erase(temp_list.begin() + j);
                    break;
                }
            }
            j++;
        }
        if(j == server_list.size())
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
