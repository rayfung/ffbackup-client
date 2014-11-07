#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <string>
#include <iostream>
#include <vector>
#include <map>

#include "client.h"
#include "helper.h"
#include "ffbuffer.h"
#include "file_info.h"
#include "config.h"

#include <librsync.h>

#include <openssl/bio.h>
#include <openssl/err.h>


using namespace std;


#define SSL_DFLT_HOST  "localhost"
#define SSL_DFLT_PORT  "16903"
#define MAX_BUFFER_SIZE 1024

extern const char *CFG_PATH;
extern char *optarg;

static void sigpipe_handle( int );
static int  ip_connect(int type, int protocol, const char *host, const char *serv);
static void check_certificate( SSL *, int );
static void client_request(int sock, SSL *);

static vector<file_info> local_list;
static vector<file_info> server_list;
static vector<file_info> diff_list;
static vector<file_info> addition_list;
static vector<file_info> deletion_list;
static vector<file_info> delta_list;

static char version = 2;
client_config g_config;

static int password_cb( char *buf, int num, int rwflag, void *userdata )
{
    char password[] = "ffbackup";
    int len = strlen( password );

    if ( num < len + 1 )
        len = 0;
    else
        strcpy( buf, password );

    return( len );
}

int main( int argc, char **argv )
{
    int c,sock;
    SSL_CTX *ctx;
    const SSL_METHOD *meth;
    SSL *ssl;
    BIO *sbio;
    const char *cafile = NULL;
    const char *cadir = NULL;
    const char *certfile = NULL;
    const char *keyfile = NULL;
    const char *host = NULL;
    const char *port = NULL;
    const char *cwd = NULL;

    while( (c = getopt( argc, argv, "hf:" )) != -1 )
    {
        switch(c)
        {
        case 'h':
            printf("-f <path>\tConfiguration file path\n");
            printf("-h       \tShow this help\n");
            exit(0);

        case 'f':
            if(!(CFG_PATH = strdup(optarg)))
                die("Out of memory");
            break;

        default:
            exit(1);
        }
    }

    if(!g_config.read_config(CFG_PATH))
        exit(1);

    host     = g_config.get_host();
    port     = g_config.get_service();
    cafile   = g_config.get_ca_file();
    certfile = g_config.get_cert_file();
    keyfile  = g_config.get_key_file();
    cwd      = g_config.get_backup_path();

    if(cwd == NULL || cwd[0] == '\0')
    {
        fprintf(stderr, "backup path is invalid.\n");
        exit(1);
    }
    if(chdir(cwd) < 0)
    {
        perror("chdir");
        exit(1);
    }

    /* Initialize SSL Library */
    SSL_library_init();
    SSL_load_error_strings();

    /* Set up a SIGPIPE handler */
    signal( SIGPIPE, sigpipe_handle );

    /* Create SSL context*/
    meth = TLSv1_method();

    ctx = SSL_CTX_new( meth );

    /* Load the CAs we trust*/
    if ( (cafile || cadir)  &&
            ! SSL_CTX_load_verify_locations( ctx, cafile, cadir ) )
        die( "Can't read CA list" );

    /* Load certificates */
    if ( certfile && ! SSL_CTX_use_certificate_chain_file( ctx, certfile ) )
        die( "Can't read certificate file" );

    SSL_CTX_set_default_passwd_cb( ctx, password_cb );
    if ( keyfile )
    {
        /* Load private key */
        if ( ! SSL_CTX_use_PrivateKey_file( ctx, keyfile, SSL_FILETYPE_PEM ) )
            die( "Can't read key file" );
    }

    sock = ip_connect( SOCK_STREAM, IPPROTO_TCP, host, port );
    if(sock == -1)
        exit(1);

    /* Associate SSL connection with server socket */
    ssl = SSL_new( ctx );
    sbio = BIO_new_socket( sock, BIO_NOCLOSE );
    SSL_set_bio( ssl, sbio, sbio );

    /* Perform SSL client connect handshake */
    if ( SSL_connect( ssl ) <= 0 )
        die( "SSL connect error" );

    check_certificate( ssl, 1 );

    /* Now make our request */
    client_request(sock, ssl);

    /* Shutdown SSL connection */
    if(SSL_shutdown( ssl ) == 0)
    {
        shutdown(sock, SHUT_WR);
        if(SSL_shutdown(ssl) != 1)
            fprintf(stderr, "SSL_shutdown failed\n");
    }
    SSL_free( ssl );
    SSL_CTX_free(ctx);
    close( sock );

    exit(0);
}

static void sigpipe_handle( int x )
{
}


/**
 * create a socket
 * and connect to host:serv (TCP)
 * or set the default destination host:serv (UDP)
 *
 * type: SOCK_STREAM or SOCK_DGRAM
 * protocol: IPPROTO_TCP or IPPROTO_UDP
 * host: host name of remote host
 * serv: service name
 *
 * On success, a file descriptor for the new socket is returned
 * On error, -1 is returned
 */
static int ip_connect(int type, int protocol, const char *host, const char *serv)
{
    struct addrinfo hints, *res, *saved;
    int n, sockfd;

    bzero(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = type;
    hints.ai_protocol = protocol;
    n = getaddrinfo(host, serv, &hints, &res);
    if(n != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(n));
        return -1;
    }
    saved = res;
    while(res)
    {
        sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if(sockfd >= 0)
        {
            if(connect(sockfd, res->ai_addr, res->ai_addrlen) == 0)
                break;
        }
        res = res->ai_next;
    }
    if(res == NULL)
    {
        perror("ip_connect");
        sockfd = -1;
    }
    freeaddrinfo(saved);
    return sockfd;
}


static void check_certificate( SSL *ssl, int required )
{
    X509 *peer;

    /* Verify server certificate */
    if ( SSL_get_verify_result( ssl ) != X509_V_OK )
        die( "Certificate doesn't verify" );

    /* Check the common name */
    peer = SSL_get_peer_certificate( ssl );

    if ( ! peer  &&  required )
        die( "No peer certificate" );
}


/**
 * the error's output
 * msg: the errno message
 */
void die(const char *msg)
{
    fprintf(stderr, "%s\n", msg);
    exit(1);
}


/* 从服务端获取文件列表，然后和本地文件列表作对比，确定新增文件列表、变化文件列表和删除文件列表 */
void start_backup(SSL *ssl)
{
    const char *project_name = g_config.get_project_name();
    const char *project_path = g_config.get_backup_path();
    char buffer[2];
    char command = 0x01;
    buffer[0] = version;
    buffer[1] = command;
    ssl_write_wrapper(ssl, buffer, 2);
    ssl_write_wrapper(ssl, project_name, strlen(project_name) + 1);
    ssl_read_wrapper(ssl, buffer, 2);
    server_list = get_server_list(ssl);
    local_list = get_local_list(project_path);
    list_compare(local_list, server_list, addition_list, diff_list, deletion_list);
    simplify_deletion_list(deletion_list);
}

/* 从服务端获取变化文件列表中的所有文件的 SHA-1 哈希值 */
void get_hash(SSL *ssl)
{
    char buffer[2];
    char command = 0x02;
    uint32_t file_count = 0;
    unsigned int i = 0;
    unsigned char sha[20];

    buffer[0] = version;
    buffer[1] = command;
    ssl_write_wrapper(ssl, buffer, 2);
    file_count = diff_list.size();
    file_count = hton32(file_count);
    ssl_write_wrapper(ssl, &file_count, 4);
    while(i < diff_list.size())
    {
        ssl_write_wrapper(ssl, diff_list.at(i).get_path(), strlen(diff_list.at(i).get_path()) + 1);
        i++;
    }
    
    ssl_read_wrapper(ssl, buffer, 2);
    ssl_read_wrapper(ssl, &file_count, 4);
    file_count = ntoh32(file_count);
    i = 0;
    while(i < file_count)
    {
        ssl_read_wrapper(ssl, sha, 20);
        diff_list.at(i).set_sha1(sha);
        i++;
    }
    find_delta_list(diff_list, delta_list);
}

/* 从服务端获取变化文件列表中的文件的 rsync 签名 */
void get_signature(SSL *ssl)
{
    char buffer[2];
    char command = 0x03;
    uint32_t file_count = 0;
    uint64_t file_size = 0;
    uint64_t total_read = 0;
    char sig_buffer[MAX_BUFFER_SIZE];
    int i = 0;
    char sig_name[256];
    int sig_fd;

    buffer[0] = version;
    buffer[1] = command;
    ssl_write_wrapper(ssl, buffer, 2);
    file_count = delta_list.size();
    file_count = hton32(file_count);
    ssl_write_wrapper(ssl, &file_count, 4);

    //ignore header
    ssl_read_wrapper(ssl, buffer, 2);
    ssl_read_wrapper(ssl, &file_count, 4);

    i = 0;
    while(i < (int)delta_list.size())
    {
        ssl_write_wrapper(ssl, delta_list.at(i).get_path(),
                          strlen(delta_list.at(i).get_path()) + 1);
        strcpy(sig_name, "/tmp/ffbackup-client-XXXXXX");
        sig_fd = mkstemp(sig_name);
        if(sig_fd < 0)
        {
            perror("mkstemp");
            exit(1);
        }
        delta_list.at(i).set_sig_path(sig_name);
        ssl_read_wrapper(ssl, &file_size, 8);
        file_size = ntoh64(file_size);
        while((total_read + MAX_BUFFER_SIZE) < file_size)
        {
            ssl_read_wrapper(ssl, sig_buffer, MAX_BUFFER_SIZE);
            write(sig_fd, sig_buffer, MAX_BUFFER_SIZE);
            total_read += MAX_BUFFER_SIZE;
        }
        if(total_read != file_size)
        {
            ssl_read_wrapper(ssl, sig_buffer, file_size - total_read);
            write(sig_fd, sig_buffer, file_size - total_read);
        }
        close(sig_fd);
        total_read = 0;
        i++;
    }
}

/* 发送差异数据 */
void send_delta(SSL *ssl)
{
    uint32_t i = 0;
    char buffer[2];
    char command = 0x04;
    uint32_t file_count = 0;

    file_count = delta_list.size();
    file_count = hton32(file_count);
    buffer[0] = version;
    buffer[1] = command;
    ssl_write_wrapper(ssl, buffer, 2);
    ssl_write_wrapper(ssl, &file_count, 4);
    for(i = 0; i < delta_list.size(); ++i)
    {
        send_file_delta(delta_list.at(i).get_path(),
                           delta_list.at(i).get_sig_path(), ssl);
        unlink(delta_list.at(i).get_sig_path());
    }
    ssl_read_wrapper(ssl, buffer, 2);
}

/* 发送新增的文件 */
void send_addition_fn(SSL *ssl)
{
    char buffer[2];
    char command = 0x06;
    uint32_t i = 0;
    uint32_t file_count = 0;
    buffer[0] = version;
    buffer[1] = command;
    ssl_write_wrapper(ssl, buffer, 2);
    file_count = addition_list.size();
    file_count = hton32(file_count);
    ssl_write_wrapper(ssl, &file_count, 4);
    while(i < addition_list.size())
    {
        send_file_addition(addition_list.at(i).get_path(), ssl);
        i++;
    }
    ssl_read_wrapper(ssl, buffer, 2);
}

/* 发送删除文件列表 */
void send_deletion(SSL *ssl)
{
    char buffer[2];
    uint32_t i = 0;
    uint32_t file_count = 0;
    char command = 0x05;
    file_count = deletion_list.size();
    file_count = hton32(file_count);
    buffer[0] = version;
    buffer[1] = command;
    ssl_write_wrapper(ssl, buffer, 2);
    ssl_write_wrapper(ssl, &file_count, 4);
    while(i < deletion_list.size())
    {
        ssl_write_wrapper(ssl, deletion_list.at(i).get_path(), strlen(deletion_list.at(i).get_path()) + 1);
        i++;
    }
    ssl_read_wrapper(ssl, buffer, 2);
}


/* 通知服务端备份已完成 */
void finish_backup(int sock, SSL *ssl)
{
    char buffer[2];
    char command = 0x07;
    buffer[0] = version;
    buffer[1] = command;
    ssl_write_wrapper(ssl, buffer, 2);
    ssl_read_wrapper(ssl, buffer, 2);
    if(SSL_shutdown( ssl ) == 0)
    {
        shutdown(sock, SHUT_WR);
        if(SSL_shutdown( ssl ) == 1)
        {
            printf("Done!\n");
            exit(0);
        }
        else
        {
            fputs("SSL_shutdown error.\n",stderr);
            exit(1);
        }
    }
    else
    {
        fputs("SSL_shutdown error.\n",stderr);
        exit(1);
    }
}

/**
 * client ask to backup the project
 * ssl: the ssl to communicate with the server
 */
static void client_request(int sock, SSL *ssl)
{
    fprintf(stderr, "%s", "[  0 %] start_backup...\n");
    start_backup(ssl);

    fprintf(stderr, "%s", "[  5 %] get_hash...\n");
    get_hash(ssl);

    fprintf(stderr, "%s", "[ 20 %] get_signature...\n");
    get_signature(ssl);

    fprintf(stderr, "%s", "[ 40 %] send_delta...\n");
    send_delta(ssl);

    fprintf(stderr, "%s", "[ 65 %] send_deletion...\n");
    send_deletion(ssl);

    fprintf(stderr, "%s", "[ 70 %] send_addition...\n");
    send_addition_fn(ssl);

    fprintf(stderr, "%s", "[ 90 %] finish_backup...\n");
    finish_backup(sock, ssl);
}
