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
#include "commonfunctions.h"
#include "file_info.h"
#include "scan_dir.h"
#include "send_addition.h"
#include "send_diff.h"
#include "restore.h"

#include <librsync.h>

#include <openssl/bio.h>
#include <openssl/err.h>


using namespace std;


#define SSL_DFLT_HOST  "localhost"
#define SSL_DFLT_PORT  "16903"
#define MAX_BUFFER_SIZE 1024

extern const char *CFG_PATH;
extern char *optarg;
static BIO  *bio_err = 0;
static int  verbose = 0;

static int  err_exit( const char * );
static int  ssl_err_exit( const char * );
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

static int password_cb( char *buf, int num, int rwflag, void *userdata )
{
    char password[] = "client";
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
    char *cafile = NULL;
    char *cadir = NULL;
    char *certfile = NULL;
    char *keyfile = NULL;
    const char *host = NULL;
    const char *port = NULL;
    int tlsv1 = 0;

    while( (c = getopt( argc, argv, "c:e:k:d:hp:t:Tvf:" )) != -1 )
    {
        switch(c)
        {
            case 'h':
                printf( "-T\t\tTLS v1 protocol\n" );
                printf( "-t <host>\tTarget host name (default 'localhost')\n" );
                printf( "-p <port>\tTarget port number (default 16903)\n" );
                printf( "-c <file>\tCA certificate file\n" );
                printf( "-e <file>\tCertificate file\n" );
                printf( "-k <file>\tPrivate key file\n" );
                printf( "-d <dir>\tCA certificate directory\n" );
                printf("-i <instruction>\tInstruction name\n");
                printf("-o <path>\tOutput file path\n");
                printf("-f <path>\tConfiguration file path\n");
                printf( "-v\t\tVerbose\n" );
                exit(0);

            case 't':
                if ( ! (host = strdup( optarg )) )
                    err_exit( "Out of memory" );
                break;

            case 'p':
                if ( ! (port = strdup( optarg )) )
                    err_exit( "Invalid port specified" );
                break;

            case 'd':
                if ( ! (cadir = strdup( optarg )) )
                    err_exit( "Out of memory" );
                break;

            case 'c':
                if ( ! (cafile = strdup( optarg )) )
                    err_exit( "Out of memory" );
                break;

            case 'e':   /* Certificate File */
                if ( ! (certfile = strdup( optarg )) )
                    err_exit( "Out of memory" );
                break;

            case 'k':
                if ( ! (keyfile = strdup( optarg )) )
                    err_exit( "Out of memory" );
                break;
            case 'f':
                if(!(CFG_PATH = strdup(optarg)))
                    err_exit("Out of memory");
                break;

            case 'T':  tlsv1 = 1;       break;
            case 'v':  verbose = 1;     break;
        }
    }

    if(cafile == NULL)
        cafile = read_item("CA_certificate_file");
    if(certfile == NULL)
        certfile = read_item("Certificate_file");
    if(keyfile == NULL)
        keyfile = read_item("Private_key_file");
    if(host == NULL)
        host = read_item("Target_host");
    if(port == NULL)
        port = read_item("Target_port");

    /* Initialize SSL Library */
    SSL_library_init();
    SSL_load_error_strings();

    /* Error message output */
    bio_err = BIO_new_fp( stderr, BIO_NOCLOSE );

    /* Set up a SIGPIPE handler */
    signal( SIGPIPE, sigpipe_handle );

    /* Create SSL context*/
    if ( tlsv1 )
        meth = TLSv1_method();
    else
        meth = SSLv23_method();

    ctx = SSL_CTX_new( meth );

    /* Load the CAs we trust*/
    if ( (cafile || cadir)  &&
            ! SSL_CTX_load_verify_locations( ctx, cafile, cadir ) )
        ssl_err_exit( "Can't read CA list" );

    /* Load certificates */
    if ( certfile && ! SSL_CTX_use_certificate_chain_file( ctx, certfile ) )
        ssl_err_exit( "Can't read certificate file" );

    SSL_CTX_set_default_passwd_cb( ctx, password_cb );
    if ( keyfile )
    {
        printf("load key file %s\n", keyfile);
        /* Load private key */
        if ( ! SSL_CTX_use_PrivateKey_file( ctx, keyfile, SSL_FILETYPE_PEM ) )
            ssl_err_exit( "Can't read key file" );
    }

    sock = ip_connect( SOCK_STREAM, IPPROTO_TCP, host, port );

    /* Associate SSL connection with server socket */
    ssl = SSL_new( ctx );
    sbio = BIO_new_socket( sock, BIO_NOCLOSE );
    SSL_set_bio( ssl, sbio, sbio );

    if ( verbose )
    {
        const char *str;
        int i;

        printf( "Ciphers: \n" );

        for( i = 0; (str = SSL_get_cipher_list( ssl, i )); i++ )
            printf( "    %s\n", str );
    }

    /* Perform SSL client connect handshake */
    if ( SSL_connect( ssl ) <= 0 )
        ssl_err_exit( "SSL connect error" );

    check_certificate( ssl, 1 );

    if ( verbose )
        printf( "Cipher: %s\n", SSL_get_cipher( ssl ) );

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

static int err_exit( const char *string )
{
    fprintf( stderr, "%s\n", string );
    exit(0);
}

static int ssl_err_exit( const char *string )
{
    BIO_printf( bio_err, "%s\n", string );
    ERR_print_errors( bio_err );
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
        ssl_err_exit( "Certificate doesn't verify" );

    /* Check the common name */
    peer = SSL_get_peer_certificate( ssl );

    if ( ! peer  &&  required )
        err_exit( "No peer certificate" );
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


/**
*the client start backup and send the files list to the server
*ssl: the sock to write data to the server
*/
void start_backup(SSL *ssl)
{
    char *project_name = read_item("Project");
    char *project_path = read_item("Path");
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
    free(project_path);
    free(project_name);
}

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

void get_signature(SSL *ssl)
{
    char buffer[2];
    char command = 0x03;
    uint32_t file_count = 0;
    uint64_t file_size = 0;
    uint64_t total_read = 0;
    char sig_buffer[MAX_BUFFER_SIZE];
    int i = 0;
    char sig_name[32];
    FILE *sig_file;
    char *sig_dir = read_item("Sig");
    string name;
    if(!sig_dir)
    {
        fputs("Read_item error.\n",stderr);
        exit(1);
    }
    if(chdir(sig_dir) == -1)
    {
        fputs("Chdir error.\n",stderr);
        exit(1);
    }

    buffer[0] = version;
    buffer[1] = command;
    ssl_write_wrapper(ssl, buffer, 2);
    file_count = delta_list.size();
    file_count = hton32(file_count);
    ssl_write_wrapper(ssl, &file_count, 4);
    
    while(i < (int)delta_list.size())
    {
        ssl_write_wrapper(ssl, delta_list.at(i).get_path(), strlen(delta_list.at(i).get_path()) + 1);
        i++;
    }
    ssl_read_wrapper(ssl, buffer, 2);
    ssl_read_wrapper(ssl, &file_count, 4);
    file_count = ntoh32(file_count);
    i = 0;
    printf("file_count in get_sig:%d\n",file_count);
    while(i < (int)file_count)
    {
        sprintf(sig_name, "%d", i);
        name.append(sig_dir);
        name.append("/");
        name.append(sig_name);
        printf("name in get_sig:%s\n",name.c_str());
        delta_list.at(i).set_sig_path(name.c_str());
        name.clear();
        sig_file = fopen(sig_name, "wb");
        if(!sig_file)
        {
            fputs("Fopen error.\n",stderr);
            exit(1);
        }
        ssl_read_wrapper(ssl, &file_size, 8);
        file_size = ntoh64(file_size);
        while((total_read + MAX_BUFFER_SIZE) < file_size)
        {
            ssl_read_wrapper(ssl, sig_buffer, MAX_BUFFER_SIZE);
            fwrite(sig_buffer, 1, MAX_BUFFER_SIZE, sig_file);
            total_read += MAX_BUFFER_SIZE;
        }
        if(total_read != file_size)
        {
            ssl_read_wrapper(ssl, sig_buffer, file_size - total_read);
            fwrite(sig_buffer, 1, file_size - total_read, sig_file);
        }
        fclose(sig_file);
        total_read = 0;
        i++;
    }
    free(sig_dir);
    if(chdir("..") == -1)
    {
        fputs("Chdir error.\n",stderr);
        exit(1);
    }
}

void send_delta(SSL *ssl)
{
    char *project_path = read_item("Path");
    uint32_t i = 0;
    char buffer[2];
    char command = 0x04;
    uint32_t file_count = 0;
    send_diff to_send;
    if(!project_path)
    {
        fputs("Read_item error.\n",stderr);
        exit(1);
    }
    if(chdir(project_path) == -1)
    {
        fputs("Chdir error.\n",stderr);
        exit(1);
    }
    file_count = delta_list.size();
    file_count = hton32(file_count);
    buffer[0] = version;
    buffer[1] = command;
    ssl_write_wrapper(ssl, buffer, 2);
    ssl_write_wrapper(ssl, &file_count, 4);
    for(i = 0; i < delta_list.size(); ++i)
    {
        to_send.send_delta(delta_list.at(i).get_path(),
                           delta_list.at(i).get_sig_path(), ssl);
    }
    ssl_read_wrapper(ssl, buffer, 2);
    free(project_path);
    if(chdir("..") == -1)
    {
        fputs("Chdir error.\n",stderr);
        exit(1);
    }
}

void send_addition_fn(SSL *ssl)
{
    char *project_path = read_item("Path");
    char buffer[2];
    char command = 0x06;
    uint32_t i = 0;
    uint32_t file_count = 0;
    send_addition to_send(project_path);
    buffer[0] = version;
    buffer[1] = command;
    ssl_write_wrapper(ssl, buffer, 2);
    file_count = addition_list.size();
    file_count = hton32(file_count);
    ssl_write_wrapper(ssl, &file_count, 4);
    while(i < addition_list.size())
    {
        to_send.send_to_server(addition_list.at(i).get_path(), ssl);
        i++;
    }
    ssl_read_wrapper(ssl, buffer, 2);
    printf("command in send_addition_fn:%d\n",(int)buffer[1]);
    free(project_path);
}

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
    printf("command in send_deletion:%d\n",(int)buffer[1]);
}



void finish_backup(int sock, SSL *ssl)
{
    char buffer[2];
    char command = 0x07;
    buffer[0] = version;
    buffer[1] = command;
    ssl_write_wrapper(ssl, buffer, 2);
    ssl_read_wrapper(ssl, buffer, 2);
    printf("command in finish_backup:%d\n",buffer[1]);
    if(SSL_shutdown( ssl ) == 0)
    {
        shutdown(sock, SHUT_WR);
        if(SSL_shutdown( ssl ) == 1)
        {
            printf("All finished.\n");
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
 * file_path: the spy program use it to store the information of the current program 
 * instruction: the instruction that the client want to excuate 
 */
static void client_request(int sock, SSL *ssl)
{
    char code = 0x02;

    start_backup(ssl);
    while(1)
    {
        switch(code)
        {
            case 0x02:
                get_hash(ssl);
                code = 0x03;
                break;
            case 0x03:
                get_signature(ssl);
                code = 0x04;
                break;
            case 0x04:
                send_delta(ssl);
                code = 0x05;
                break;
            case 0x05:
                send_deletion(ssl);
                code = 0x06;
                break;
            case 0x06:
                send_addition_fn(ssl);
                code = 0x07;
                break;
            case 0x07:
                finish_backup(sock, ssl);
                code = 0x08;
                break;
            default:
                fputs("Error code to excuate.\n",stderr);
                exit(1);
        }
    }
}
