#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "common.h"

#define HOST "localhost"
#define PORT 5555
static char *REQUEST_TEMPLATE=
   "GET / HTTP/1.0\r\nUser-Agent:"
   "EKRClient\r\nHost: %s:%d\r\n\r\n";

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"

#define BUFSIZE 256
#define CLIENT_KEYFILE "alice.pem"
#define CLIENT_PASSWORD "password"
#define EMAIL "ece568bob@ecf.utoronto.ca"
#define SERVER_CN "Bob's Server"

/* Check that the common name matches the
   host name*/
void check_cert(SSL *ssl, char *host) {
  X509 *peer;
  char peer_CN[256];
  
  if (SSL_get_verify_result(ssl)!=X509_V_OK)
    berr_exit("Certificate doesn't verify");

  /*Check the cert chain. The chain length
    is automatically checked by OpenSSL when
    we set the verify depth in the ctx */

  /*Check the common name*/
  peer = SSL_get_peer_certificate(ssl);
  X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_commonName, peer_CN, 256);
  if(strcasecmp(peer_CN, SERVER_CN))
    err_exit("Common name doesn't match host name");
}

static int http_request(ssl)
  SSL *ssl;
  {
    char *request=0;
    char buf[BUFSIZE];
    int r;
    int len, request_len;
    
    /* Now construct our HTTP request */
    request_len = strlen(REQUEST_TEMPLATE)+ strlen(HOST) + 6;
    if ( !(request = (char *) malloc(request_len)) )
      err_exit("Couldn't allocate request");
    snprintf(request,request_len,REQUEST_TEMPLATE, HOST, PORT);

    /* Find the exact request_len */
    request_len=strlen(request);

    r = SSL_write(ssl, request, request_len);
    switch(SSL_get_error(ssl,r)){      
      case SSL_ERROR_NONE:
        if(request_len!=r)
          err_exit("Incomplete write!");
        break;
        default:
          berr_exit("SSL write problem");
    }
    
    /* Now read the server's response, assuming
       that it's terminated by a close */
    while(1){
      r=SSL_read(ssl,buf, BUFSIZE);
      switch(SSL_get_error(ssl,r)){
        case SSL_ERROR_NONE:
          len=r;
          break;
        case SSL_ERROR_ZERO_RETURN:
          goto shutdown;
        case SSL_ERROR_SYSCALL:
          fprintf(stderr,
            "SSL Error: Premature close\n");
          goto done;
        default:
          berr_exit("SSL read problem");
      }

      fwrite(buf,1,len,stdout);
    }
    
  shutdown:
    r=SSL_shutdown(ssl);
    switch(r){
      case 1:
        break; /* Success */
      case 0:
      case -1:
      default:
        berr_exit("Shutdown failed");
    }
    
  done:
    SSL_free(ssl);
    free(request);
    return(0);
  }

int main(int argc, char **argv) {
  int len, sock, port=PORT;
  char *host = HOST;
  struct sockaddr_in addr;
  struct hostent *host_entry;
  char buf[256];
  char *secret = "What's the question?";
  
  /*Parse command line arguments*/
  
  switch(argc){
    case 1:
      break;
    case 3:
      host = argv[1];
      port=atoi(argv[2]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s server port\n", argv[0]);
      exit(0);
  }

  SSL_CTX *ctx;
  SSL *ssl;
  BIO *sbio;
  
  ctx = initialize_ctx(CLIENT_KEYFILE, CLIENT_PASSWORD);
  
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
  SSL_CTX_set_cipher_list(ctx, "SHA1");  
  
  /*get ip address of the host ---TCP Connection*/
  
  host_entry = gethostbyname(host);
  
  if (!host_entry){
    fprintf(stderr,"Couldn't resolve host");
    exit(0);
  }

  memset(&addr,0,sizeof(addr));
  addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
  addr.sin_family=AF_INET;
  addr.sin_port=htons(port);
  
  printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);
  
  /*open socket*/
  
  if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
    perror("socket");
  if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0)
    perror("connect");
  
  
  /* Connect the SSL socket */
    ssl=SSL_new(ctx);
    sbio=BIO_new_socket(sock,BIO_NOCLOSE);
    SSL_set_bio(ssl,sbio,sbio);

    if(SSL_connect(ssl)<=0)
      berr_exit("SSL connect error");

    check_cert(ssl, host);
 
    /* Now make our HTTP request */
    http_request(ssl);


  send(sock, secret, strlen(secret),0);
  len = recv(sock, &buf, 255, 0);
  buf[len]='\0';
  
  /* this is how you output something for the marker to pick up */
  printf(FMT_OUTPUT, secret, buf);
  
  close(sock);
  return 1;
}
