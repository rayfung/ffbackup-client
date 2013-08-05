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

#include <librsync.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

//<<<<<<< Updated upstream
//=======
using namespace std;

//>>>>>>> Stashed changes
#define SSL_DFLT_HOST  "localhost"
#define SSL_DFLT_PORT  "16903"
#define MAX_BUFFER_SIZE 1024
#define CFG_FILE "/home/william/git/ffbackup/client/project.cfg"

typedef unsigned long long bigint;

extern char *optarg;
static BIO  *bio_err = 0;
static int  verbose = 0;

static int  err_exit( const char * );
static int  ssl_err_exit( const char * );
static void sigpipe_handle( int );
static int  ip_connect(int type, int protocol, const char *host, const char *serv);
static void check_certificate( SSL *, int );
static void client_request( SSL *, const char *, int );

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
    int c, sock;
    SSL_CTX *ctx;
    const SSL_METHOD *meth;
    SSL *ssl;
    BIO *sbio;
    char *cafile = NULL;
    char *cadir = NULL;
    char *certfile = NULL;
    char *keyfile = NULL;
    const char *host = SSL_DFLT_HOST;
    const char *port = SSL_DFLT_PORT;
    int tlsv1 = 0;
    while( (c = getopt( argc, argv, "c:e:k:d:hp:t:Tv" )) != -1 )
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
    client_request( ssl, host, atoi(port) );

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
 * recover the project which has not been finished last time
 * ssl: the sock to write data to the server
 */
void client_recover_backup(SSL *ssl)
{
	char buf[MAX_BUFFER_SIZE];
    int r, len;
	//char *value = read_item("/home/william/Scan/","Project");
	//value indicates the project to recover
	char *value = (char *)malloc( MAX_BUFFER_SIZE * sizeof(char) );
	printf("Please input the project you want to recover.\n");
	gets(value);
	char version = 1;
	char command = 0x05;
	sprintf(buf,"%c%c%s",version,command,value); 
    len = strlen(buf);
    r = SSL_write(ssl, buf, len);
    switch(SSL_get_error(ssl, r))
    {
        case SSL_ERROR_NONE:
            if ( len != r )
			{
				free(value);
                err_exit("Incomplete write!");
			}            
			break;
        default:
			free(value);
            ssl_err_exit( "SSL write problem" );
    }
	//To get the return code
    r = SSL_read( ssl, buf, sizeof( buf ) - 1 );
	free(value);
	if(buf[1] == 0x03)
	{
		ssl_err_exit("Project doesn't exist.\n");
	}
	else if(buf[1] == 0x04)
	{
		ssl_err_exit("The backup process can not be recovered.\n");
	}
}


/**
 * the client response to the server_request_whole_file() function
 * ssl: the sock to write data to the server
 * received_buffer: the received_buffer from the server
 * test_finished_time: 2013-7-7 11:00
 */
void client_response_whole_file(SSL *ssl, const char *received_buffer)
{
	char *project_path = read_item(CFG_FILE,"Path");
	write_data send_data(project_path);
	send_data.write_to_server(&received_buffer[2],ssl);	
}


/**
 * convert the char * array to unsigned long long
 * to_convert: the buffer to convert
 * return_value:
 * return the Big-Endian unsigned long long value of the to_convert
 */
bigint convert_char_to_bigint(char *to_convert)
{
    
    bigint result = 0;
    int i = 0;
    for(i = 0; i < 8; i++)
    {
        printf("%02x",to_convert[i]);
        result |= to_convert[i];
    }
    printf("\n");
    return result;
}


/**
 * calculate the signature's buffer's delta
 * sig_buffer: the signature buffer received from the server
 * new_file_path: the new file's path which to be calculate the delta
 * delta_buffer: store the delta_file's buffer
 * length: the length of the sig_buffer to write
 * return_value:
 * the size of the delta_buffer
 */
long delta_file(const char *sig_buffer, const char *new_file_path, char *delta_buffer, bigint length)
{
	long lsize;
	size_t result;
	FILE *sig_file;
	FILE *new_file;
	FILE *delta_file;
	rs_result ret;
	rs_signature_t *sumset;
	rs_stats_t stats;

    //the original one is
    sig_file = fopen("/home/william/Scan/sig_file1.txt","wb+");
	//sig_file = fopen("/home/william/Scan/sig_file.txt", "rb");
	//new_file = fopen(new_file_path, "rb");
	new_file = fopen("/home/william/Scan/test_file.txt","rb");
    delta_file = fopen("/home/william/Scan/delta_file.txt", "wb+");
	fwrite(sig_buffer, sizeof(char), length, sig_file);
    fflush(sig_file);
    rewind(sig_file);
    fseek(sig_file, 0L, SEEK_END);
    lsize = ftell(sig_file);
    rewind(sig_file);
	ret = rs_loadsig_file(sig_file, &sumset, &stats);
	if(ret != RS_DONE)
	{
		puts(rs_strerror(ret));
		exit(1);
	}
	rs_log_stats(&stats);

	if(rs_build_hash_table(sumset) != RS_DONE)
	{
		puts(rs_strerror(ret));
		exit(1);
	}

	if(rs_delta_file(sumset, new_file, delta_file, &stats) != RS_DONE)
	{
		puts(rs_strerror(ret));
		exit(1);
	}
	fseek (delta_file , 0 , SEEK_END);
  	lsize = ftell(delta_file);
  	rewind(delta_file);

    printf("1\n");
  	// allocate memory to contain the whole file:
  	delta_buffer = (char*) malloc (sizeof(char)* lsize );
  	if (delta_buffer == NULL)
	{
		fputs ("Memory error",stderr);
		exit (1);
	}

  	// copy the file into the buffer:
  	result = fread(delta_buffer,1,lsize,delta_file);
  	if (result != (unsigned int)lsize)
	{
		fputs("Reading error",stderr);
		exit (1);
	}
    printf("2\n");
	rs_log_stats(&stats);

	rs_free_sumset(sumset);
	fclose(sig_file);
	fclose(new_file);
	fclose(delta_file);
    return lsize;
}


/**
 * the client response to the server_request_file_diff() function
 * ssl: the sock to write data to the server
 * received_buffer: the buffer received from the server 
 */
void client_response_file_diff(SSL *ssl, const char *received_buffer)
{
    struct stat info;
	FILE *pf;
    char *buf;
    //length: the length of signature or the send_buffer's length
    bigint length;
    bigint temp_length = 0;
    char *delta_buffer;
    char to_convert[8];
    int i;
    long lsize;
    //len: the length of the path pluse command & version & 8 bits
    size_t len;
    int r;
	char version,return_code;
    //path: the file's path
    char path[MAX_BUFFER_SIZE];
    strcpy(path,&received_buffer[2]);
    stat(path, &info);
    if(!S_ISREG(info.st_mode))
    {
        return ;
    }
    
    pf = fopen(path, "r");
    //length: the sig's length
    len = strlen(path);
    len += 3;
    for(i = 0; i < 8; i++)
        to_convert[i] = received_buffer[len++];
    memcpy(&length, to_convert, 8);
	version = 1;
    if(!pf)
    {
        return ;
    }
    fclose(pf);
    lsize = delta_file(&received_buffer[len], path, delta_buffer,length);
    buf = (char *)malloc( lsize +  11);
    if(!buf)
    {
        fputs("Memory error.\n",stderr);
        exit(1);
    }
	return_code = 0x04;
	sprintf(buf,"%c%c",version,return_code);
    temp_length = (bigint)lsize;
    memcpy(&buf[2], &temp_length, 8);
    memcpy(&buf[10], delta_buffer,lsize);
	length = lsize + 10; 
    r = SSL_write(ssl, buf, length);
	free(buf);
    free(delta_buffer);
    switch( SSL_get_error(ssl, r) )
    {
        case SSL_ERROR_NONE:
			if(len != (unsigned int)r)
                err_exit("Incomplete write!");
            break;

        default:
            ssl_err_exit( "SSL write problem" );
    }
}


/**
*the client start backup and send the files list to the server
*ssl: the sock to write data to the server
*/
void client_start_backup(SSL *ssl)
{
	scan_dir scan(CFG_FILE);
	char *project_path = read_item(CFG_FILE,"Path");
	scan.scan_the_dir(project_path,-1);
	scan.send_file_list(ssl);
}

/**
*the client decode the buffer which was read from the server
*ssl: the ssl should be passed to the function to execute
*buffer: the buffer which was read from the server should be decoded to decide which function should be use
*/
void decode_buffer(SSL *ssl, char *buffer)
{	
	//nothing to do with the version
	//char version = buffer[0];
    printf("Decode buffer now...\n");
	char code = buffer[1];
    if(buffer[0] == 1)
        printf("decode_buffer: version is 1\n");
    char *path;
	switch(code)
	{
		//the client to send the files' list to the server
		case 0x01:
            client_start_backup(ssl);
		break;
		
		//to check the network connection whether is OK
		case 0x02:
		break;
		
		//the client has to response the server_request_whole_file() function
        case 0x03:
        printf("OC is 0x03\n");
        client_response_whole_file(ssl, buffer);
        break;
		
		//the client has to response the server_request_file_diff() function
        case 0x04:
        printf("OC is 0x04\n");
        //path.insert(0, &buffer[2]);
        client_response_file_diff(ssl, buffer);
        break;
		
		//the client sends the recover request to server
        case 0x05:
        break;

		//the server notifies the client that the backup has been finished
        case 0x06:
        //should I shutdown and free the ssl here?
        break;
	}
}


/**
 * client ask to backup the project
 * ssl: the ssl to communicate with the server
 * host: the local ip
 * port: the local port
 * test_finished_time: 2013-7-7 9:30
 */
static void client_request( SSL *ssl, const char *host, int port )
{
    printf("client_request...\n");
    char buf[MAX_BUFFER_SIZE];
    char buffer_to_decode[MAX_BUFFER_SIZE];
    int r, len;
    buffer_to_decode[0] = 1;
    buffer_to_decode[1] = 0x03;
    strcpy(&buffer_to_decode[2],"1.txt");
    decode_buffer(ssl, buffer_to_decode);
}
