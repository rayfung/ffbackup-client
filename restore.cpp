#include "restore.h"
#include "commonfunctions.h"
#include "ffbuffer.h"
#include <librsync.h>
restore::restore(const char *path)
{
    size_t length = strlen(path);
    if(!length)
    {
        fputs("File path is NULL.\n",stderr);
        exit(1);
    }
    file_path = (char *)malloc( length + 1);
    if(!file_path)
    {
        fputs("Malloc error.\n",stderr);
        exit(1);
    }
    strcpy(file_path, path);
}

void restore::client_get_prj(SSL *ssl)
{
    char version = 1;
    char command = 0x07;
    char buf[2];
    uint32_t list_length;
    FILE *fp;
    char *project_name;
    buf[0] = version;
    buf[1] = command;
    ssl_write_wrapper(ssl, buf, 2);
    ssl_read_wrapper(ssl,&list_length, 4);
    list_length = ntoh32(list_length);
    if((fp = fopen(file_path, "w")) == NULL)
    {
        fputs("Can not open the project_list_file.\n",stderr);
        exit(1);
    }
    fwrite("Project_list_length = ", 1, strlen("Project_list_length = "), fp);
    fwrite(&list_length, 1, 4, fp);
    if(!list_length)
        return;
    fwrite("\n", 1, 1, fp);
    while(--list_length)
    {
        project_name = read_string(ssl);
        project_list.push_back(project_name);
        fwrite(project_name, 1, strlen(project_name) + 1, fp);
        fwrite("\n", 1, 1, fp);
        free(project_name);
    }
    project_name = read_string(ssl);
    project_list.push_back(project_name);
    fwrite(project_name, 1, strlen(project_name) + 1, fp);
    free(project_name);
    fclose(fp);
}

void restore::client_get_time_line(SSL *ssl)
{
    char version = 1;
    char command = 0x08;
    char buf[2];
    int i = 0;
    uint32_t list_length = 0;
    size_t project_list_length = project_list.size();
    if(project_list_length == 0)
    {
        fputs("File list is NULL.\n",stderr);
        exit(1);
    }
    uint32_t time_stamp;
    buf[0] = version;
    buf[1] = command;
    FILE *fp = fopen(file_path, "a+");
    if(!fp)
    {
        fputs("Can not open the project file to write.\n",stderr);
        exit(1);
    }
    //Insert '\n' into the origin file's end
    fwrite("\n", 1, 1, fp);
    while(--project_list_length)
    {
        ssl_write_wrapper(ssl, buf, 2);
        ssl_write_wrapper(ssl, project_list.at(i).c_str(), project_list.at(i).length() + 1);
        ssl_read_wrapper(ssl, &list_length, 4);
        list_length = ntoh32(list_length);
        fwrite(project_list.at(i).c_str(), 1, project_list.at(i).length() + 1, fp);
        fwrite(" = ", 1, 3, fp);
        fwrite(&list_length, 1, 4, fp);
        fwrite("\n", 1, 1, fp);
        while(list_length)
        {
            ssl_read_wrapper(ssl, &time_stamp, 4);
            time_stamp = ntoh32(time_stamp);
            fwrite(&time_stamp, 1, 4, fp);
            fwrite("\n", 1, 1, fp);
            list_length--;
        }
        i++;
    }  
    ssl_write_wrapper(ssl, buf, 2);
    ssl_write_wrapper(ssl, project_list.at(i).c_str(), project_list.at(i).length() + 1);
    ssl_read_wrapper(ssl, &list_length, 4);
    list_length = ntoh32(list_length);
    fwrite(project_list.at(i).c_str(), 1, project_list.at(i).length() + 1, fp);
    fwrite(" = ", 1, 3, fp);
    fwrite(&list_length, 1, 4, fp);
    if(list_length != 0)
        fwrite("\n", 1, 1, fp);
    while(list_length)
    {
        ssl_read_wrapper(ssl, &time_stamp, 4);
        time_stamp = ntoh32(time_stamp);
        fwrite(&time_stamp, 1, 4, fp);
        list_length--;
        if(list_length == 0)
            break;
        else
            fwrite("\n", 1, 1, fp);
    }
}

void restore::client_restore(SSL *ssl, const char *project_name, uint32_t number)
{
    char version = 1;
    char command = 0x09;
    char buf[2];
    char file_type;
    uint32_t list_length = 0;
    const size_t MAX_BUFFER_SIZE = 1024;
    char buffer[MAX_BUFFER_SIZE];
    uint64_t var_length = 0;
    const char CFG[] = "/home/william/git/ffbackup/client/project.cfg";
    char *project_path = read_item(CFG, "Path");
    char *path;
    FILE *fp;
    FILE *temp_file;
    rs_result ret;
    rs_stats_t stats;
    if(!project_path)
    {
        fputs("Can not find the path.\n",stderr);
        exit(1);
    }
    if(chdir(project_path) == -1)
    {
        fputs("Project path is wrong.\n",stderr);
        exit(1);
    }
    free(project_path);
    buf[0] = version;
    buf[1] = command;
    ssl_write_wrapper(ssl, buf, 2);
    ssl_write_wrapper(ssl, project_name, strlen(project_name) + 1);
    number = hton32(number);
    ssl_write_wrapper(ssl, &number, 4);
    ssl_read_wrapper(ssl, &list_length, 4);
    list_length = ntoh32(list_length);
    while(list_length--)
    {
        path = read_string(ssl);
        ssl_read_wrapper(ssl, &file_type, 1);
        if(file_type == 'f')
        {
            temp_file = tmpfile();
            ssl_read_wrapper(ssl, &var_length, 8);
            var_length = ntoh64(var_length);
            while(var_length > MAX_BUFFER_SIZE)
            {
                ssl_read_wrapper(ssl, buffer, MAX_BUFFER_SIZE);
                fwrite(buffer, 1, MAX_BUFFER_SIZE, temp_file);
                var_length -= MAX_BUFFER_SIZE;
            }
            if(var_length)
            {
                ssl_read_wrapper(ssl, buffer, var_length);
                fwrite(buffer, 1, var_length, temp_file);
                var_length = 0;
            }
            fflush(temp_file);
            fp = fopen(path, "wb");
            if(!fp)
            {
                fputs("Can not open the basis_file.\n",stderr);
                exit(1);
            }
            ret = rs_patch_file(fp, temp_file, fp, &stats);
            fclose(fp);
            fclose(temp_file);
            if(ret != RS_DONE)
            {
                puts(rs_strerror(ret));
                exit(1);
            }
        }
        free(path);
    }
    if(chdir("..") == -1)
    {
        fputs("Chdir error.\n",stderr);
        exit(1);
    }
}
