#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "config.h"
#include "ffbuffer.h"

client_config::client_config()
{
    this->reset();
}

void client_config::reset()
{
    this->project_name[0] = '\0';
    this->backup_path[0]  = '\0';
    snprintf(this->host, host_max, "0.0.0.0");
    snprintf(this->service, service_max, "16903");
    snprintf(this->ca_file, path_max, "ca.crt");
    snprintf(this->cert_file, path_max, "server.crt");
    snprintf(this->key_file, path_max, "server.key");
}

/**
 *
 * 从配置文件中读取配置
 *
 * @param path 配置文件完整路径
 * @return 如果成功则返回true，否则返回false，此时的配置状态未定义
 *
 */
bool client_config::read_config(const char *path)
{
    char buffer[1024];
    int fd;
    ssize_t ret;
    ffbuffer content;
    size_t line_num;

    fd = open(path, O_RDONLY);
    if(fd == -1)
    {
        perror("open");
        return false;
    }
    while((ret = read(fd, buffer, sizeof(buffer))) > 0)
        content.push_back(buffer, ret);
    close(fd);

    line_num = 1;
    while(content.get_size() > 0)
    {
        size_t key_len;
        size_t value_len;
        size_t extra;
        size_t i;
        char key[32];
        bool found;
        const char *key_list[] = {
            "project_name", "backup_path", "host", "service",
            "ca_file", "cert_file", "key_file"
        };
        char *value_list[] = {
            this->project_name, this->backup_path, this->host, this->service,
            this->ca_file, this->cert_file, this->key_file
        };
        size_t size_list[] = {
            name_max, path_max, host_max, service_max,
            path_max, path_max, path_max
        };
        size_t item_count = 7;

        key_len = content.find('\x20', &found);
        if(found && key_len <= sizeof(key))
        {
            content.get(key, 0, key_len);
            content.pop_front(key_len);

            for(i = 0; i < content.get_size(); ++i)
            {
                unsigned char ch;
                ch = content.at(i);
                if(ch != '\x20' && ch != '\t')
                    break;
            }
            content.pop_front(i);

            value_len = content.find('\n', &found);
            if(found)
                extra = 1;
            else
                extra = 0;

            for(i = 0; i < item_count; ++i)
            {
                if(strncmp(key, key_list[i], key_len) == 0)
                {
                    if(value_len >= size_list[i])
                    {
                        fprintf(stderr, "read_config: %s too long(line %d)\n",
                                key_list[i], (int)line_num);
                        return false;
                    }
                    content.get(value_list[i], 0, value_len);
                    value_list[i][value_len] = '\0';
                    fprintf(stderr, "%s=%s\n", key_list[i], value_list[i]);
                    break;
                }
            }
            if(i >= item_count)
            {
                fprintf(stderr, "read_config: key invalid (line %d)\n", (int)line_num);
                return false;
            }
            content.pop_front(value_len + extra);
        }
        else
        {
            fprintf(stderr, "read_config: key is too long (line %d)\n", (int)line_num);
            return false;
        }
        ++line_num;
    }
    return true;
}

const char *client_config::get_project_name() const
{
    return this->project_name;
}

const char *client_config::get_backup_path() const
{
    return this->backup_path;
}

const char *client_config::get_host() const
{
    return this->host;
}

const char *client_config::get_service() const
{
    return this->service;
}

const char *client_config::get_ca_file() const
{
    return this->ca_file;
}

const char *client_config::get_cert_file() const
{
    return this->cert_file;
}

const char *client_config::get_key_file() const
{
    return this->key_file;
}

client_config::~client_config()
{
}
