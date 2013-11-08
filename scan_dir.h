#ifndef SCAN_DIR_H
#define SCAN_DIR_H

#include <stdio.h>
#include <openssl/ssl.h>
#include <vector>
#include "helper.h"
#include "file_info.h"

using namespace std;

class scan_dir
{
public:
    void scan_the_dir(const char* dir, int depth);
    vector<file_info> get_local_list();

private:
    vector<file_info> local_list;
};
#endif
