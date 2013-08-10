#include <stdlib.h>
#include <string.h>
#include "commonfunctions.h"
#include "ffbuffer.h"

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
