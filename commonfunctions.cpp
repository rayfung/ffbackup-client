#include <stdlib.h>
#include <string.h>
#include "commonfunctions.h"

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
