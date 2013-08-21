#include "get_sig.h"
#include "commonfunctions.h"
#include "helper.h"
#include <openssl/err.h>
#include <openssl/bio.h>
#include <unistd.h>

#define CFG_FILE "/home/william/git/ffbackup/client/project.cfg"

get_sig::get_sig()
{
}

void get_sig::set_from_server(vector<file_info> &file_list, SSL *ssl)
{
    //change to the sig_dir
    int i = 0;
    uint32_t file_count = 0;
    uint64_t sig_size = 0;
    uint64_t total_read = 0;
    const size_t max_buffer_size = 0;
    char buffer[max_buffer_size];
    FILE *sig_file;
    char file_name[32];
    char *sig_dir = read_item(CFG_FILE, "Sig");
    
    if(chdir(sig_dir) == -1)
    {
        fputs("Chdir error.\n",stderr);
        exit(1);
    }

    file_count = file_list.size();
    file_count = hton32(file_count);
    ssl_write_wrapper(ssl, &file_count, 4);
    while(i < (int)file_list.size())
    {
        ssl_write_wrapper(ssl, file_list.at(i).get_path(), strlen(file_list.at(i).get_path()) + 1);
        i++;
    }
    i = 0;
    ssl_read_wrapper(ssl, &file_count, 4);
    file_count = ntoh32(file_count);
    while(i < (int)file_count)
    {
        sprintf(file_name, "%d", i);
        sig_file = fopen(file_name, "wb");
        if(!sig_file)
        {
            fputs("Fopen error.\n",stderr);
            exit(1);
        }
        file_list.at(i).set_sig_path(file_name);
        ssl_read_wrapper(ssl, &sig_size, 8);
        sig_size = ntoh64(sig_size);
        while((total_read + max_buffer_size) < sig_size)
        {
            ssl_read_wrapper(ssl, buffer, max_buffer_size);
            fwrite(buffer, 1, max_buffer_size, sig_file);
            total_read += max_buffer_size;
        }
        if(total_read != sig_size)
        {
            ssl_read_wrapper(ssl, buffer, sig_size - total_read);
            fwrite(buffer, 1, sig_size - total_read, sig_file);
            total_read = sig_size;
        }
        total_read = 0;
        i++;
        fclose(sig_file);
    }
    free(sig_dir);
}
