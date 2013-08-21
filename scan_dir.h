#ifndef SCAN_DIR_H
#define SCAN_DIR_H

#include <stdio.h>
#include <openssl/ssl.h>
#include <vector>
#include "helper.h"
#include "file_info.h"

using namespace std;

/*
 * scan_dir: scan the project and store the informations in the local_list
 * dir_path: configue's path
 * local_list: the local files list
 */
class scan_dir
{
private:
    //the project's path
    char *dir_path;
    vector<file_info> local_list;
public:
    void sha1(const char*path, unsigned char *md);
    void scan_the_dir(const char* dir, int depth);
    scan_dir(const char *dir_path);
    vector<file_info> get_local_list();
};
#endif
