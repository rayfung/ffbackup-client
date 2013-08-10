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

#include "helper.h"
#include "ffbuffer.h"
#include "commonfunctions.h"
#include "sendinfo.h"
#include "writedata.h"
#include "writediff.h"

#include <librsync.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>


using namespace std;


#define SSL_DFLT_HOST  "localhost"
#define SSL_DFLT_PORT  "16903"
#define MAX_BUFFER_SIZE 1024
#define CFG_FILE "/home/william/git/ffbackup/client/project.cfg"

extern char *optarg;
static BIO  *bio_err = 0;
static int  verbose = 0;

static int  err_exit( const char * );
static int  ssl_err_exit( const char * );
static void sigpipe_handle( int );
static int  ip_connect(int type, int protocol, const char *host, const char *serv);
static void check_certificate( SSL *, int );
static void client_request(int sock, SSL *, const char *,const char *);

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
    char *file_path = NULL;
    char *instruction = NULL;
    SSL_CTX *ctx;
    const SSL_METHOD *meth;
    SSL *ssl;
    BIO *sbio;
    char *cafile = read_item(CFG_FILE,"CA_certificate_file");
    if(!cafile)
        err_exit("Can not find CA_certificate_file");
    char *cadir = NULL;
    char *certfile = read_item(CFG_FILE, "Certificate_file");
    if(!certfile)
        err_exit("Can not find Certificate_file");
    char *keyfile = read_item(CFG_FILE,"Private_key_file");
    if(!keyfile)
        err_exit("Can not find Private_key_file");
    const char *host = read_item(CFG_FILE,"Target_host");
    if(!host)
        err_exit("Can not find Target_host");
    const char *port = SSL_DFLT_PORT;
    int tlsv1 = 0;

    while( (c = getopt( argc, argv, "c:e:k:d:hp:t:Tvi:f:" )) != -1 )
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
                printf("-f <path>\tFile path\n");
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
            case 'i':
                if(!(instruction = strdup(optarg)))
                    err_exit("Out of memory");
                break;
            case 'f':
                if(!(file_path = strdup(optarg)))
                    err_exit("Out of memory");
                break;

            case 'T':  tlsv1 = 1;       break;
            case 'v':  verbose = 1;     break;
        }
    }

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
    client_request(sock, ssl, file_path, instruction );

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
void client_start_backup(SSL *ssl)
{
	scan_dir scan(CFG_FILE);
	char *project_path = read_item(CFG_FILE,"Path");
	scan.scan_the_dir(project_path, -1);
	scan.send_file_list(ssl);
    free(project_path);
}



/**
 * the client response to the server_request_whole_file() function
 * ssl: the sock to write data to the server
 */
void client_response_whole_file(SSL *ssl)
{
	ffbuffer store;
	char *pass = read_string(ssl);
	char *project_path = read_item(CFG_FILE,"Path");
	write_data send_data(project_path);
	send_data.write_to_server(pass,ssl);
	free(pass);
	return ;
}
	


/**
 * the client response to the server_request_file_diff() function
 * ssl: the sock to write data to the server
 */
void client_response_file_diff(SSL *ssl)
{
	char *project_path = read_item(CFG_FILE,"Path");
	write_diff difference(project_path);
	difference.write_to_server(ssl);
    free(project_path);
}



/**
 * recover the project which has not been finished last time
 * ssl: the sock to write data to the server
 */
void client_recover_backup(SSL *ssl)
{
	char *project_name = read_item(CFG_FILE,"Project");
    char version = 1;
    char command = 0x05;
	char buf[2];
	size_t length = 0;    
	char *to_send;
	length = strlen(project_name);
	to_send = (char *)malloc(length + 3);
	to_send[0] = version;
	to_send[1] = command;
	strcpy(&to_send[2], project_name);
    ssl_write_wrapper(ssl, to_send, length + 3);
    ssl_read_wrapper(ssl, buf, 2);
    free(project_name);
	if(buf[1] != 0x00)
		client_start_backup(ssl);
	else
		return ;
}



/**
 * client ask to backup the project
 * ssl: the ssl to communicate with the server
 * file_path: the spy program use it to store the information of the current program 
 * instruction: the instruction that the client want to excuate 
 */
static void client_request(int sock, SSL *ssl, const char *file_path, const char *instruction)
{
    if(!strcmp(instruction, "backup"))
        client_start_backup(ssl);
    else if(!strcmp(instruction, "recover"))
        client_recover_backup(ssl);
    else if(!strcmp(instruction, "restore"))
        printf("Restore from the server\n");
    else
    {
        fputs("Instruction error.\n",stderr);
        exit(1);
    }
    char buf[2];
    while(1)
    {
        ssl_read_wrapper(ssl, buf, 2);
        printf("The version from server:%02x\n",(int)buf[0]);
        printf("The command from the server:%02x\n",(int)buf[1]);
        int code = (int)buf[1];

        switch(code)
        {		
                //the client has to response the server_request_whole_file() function
            case 0x03:
                client_response_whole_file(ssl);
                break;

                //the client has to response the server_request_file_diff() function
            case 0x04:
                client_response_file_diff(ssl);
                break;

                //the server notifies the client that the backup has been finished
            case 0x06:
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

                break;
            default:
                fputs("Error command read from the server:\n",stderr);
                exit(1);
        }
    }

}
