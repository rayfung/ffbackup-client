#ifndef FILE_INFO_H
#define FILE_INFO_H
/*
 * file_info: store the information of the file
 * path: file's path
 * file_type: file or director
 */
class file_info
{
private:
    char *path;// the file's path
    char file_type;// the file's type
    char *sig_path;// the sig file's path
    char sha1[20];// the sha1 of the file
public:
    char *get_path();
    char get_file_type();
    void set_sig_path(const char *str);
    char *get_sig_path();
    void set_sha1(char *str);
    file_info(const char *path, char file_type);
};
#endif
