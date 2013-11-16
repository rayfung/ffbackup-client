#ifndef FF_CONFIG_H
#define FF_CONFIG_H

#include <sys/types.h>
#include <limits.h>

class client_config
{
public:
    client_config();
    ~client_config();
    void reset();
    bool read_config(const char *path);
    const char *get_project_name() const;
    const char *get_backup_path() const;
    const char *get_host() const;
    const char *get_service() const;
    const char *get_ca_file() const;
    const char *get_cert_file() const;
    const char *get_key_file() const;

private:
    const static size_t name_max = 64;
    const static size_t path_max = PATH_MAX;
    const static size_t host_max = 128;
    const static size_t service_max = 32;
    char project_name[name_max];       //项目名称
    char backup_path[path_max];        //备份目录
    char host[host_max];               //服务端的地址
    char service[service_max];         //服务端的端口
    char ca_file[path_max];            //CA 公钥文件路径
    char cert_file[path_max];          //客户端公钥文件路径
    char key_file[path_max];           //客户端私钥文件路径
};

#endif
