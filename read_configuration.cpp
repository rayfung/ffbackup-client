#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <unistd.h>
#include <string.h>
using namespace std;
#define MAX_BUFFER_SIZE 1024

char *read_item(char const *cfgFile, char const *item)
{

    FILE * fp;
    char buffer[MAX_BUFFER_SIZE] ;
    char *dest, *result;
    if((fp = fopen(cfgFile, "r") ) == NULL)
    {
        printf("Error! fopen function Error!\n");
        return NULL;
    }
    while(fgets(buffer, MAX_BUFFER_SIZE, fp ) != NULL )
    {
        buffer[strlen(buffer)-1] = '\0';
        if (strncmp(item, buffer, strlen(item)) == 0 )
        {
            dest = strstr(buffer, "=") + 2;
            if((result=(char *)malloc(strlen(dest))) == NULL)
            {
                printf("Cannot allocate memory for result\n");
                fclose(fp);
                return NULL;
            }
			memcpy(result, dest, strlen(dest));
			//result = dest;
            fclose(fp);
            return (result);
        }
        continue;
    }
    fclose(fp);
    printf("Cannot find the Item\n");
    return NULL;
}
