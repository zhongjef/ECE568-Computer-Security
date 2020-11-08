// reference: https://github.com/Andersbakken/openssl-examples/blob/master/
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
#define PORT 5522
#define CA_LIST "568ca.pem"


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
void check_cert(SSL *ssl) {
  X509 *peer;
  char peer_CN[256];
  char peer_email[256];
  char peer_certificate_issuer[256];

  if (SSL_get_verify_result(ssl)!=X509_V_OK)
    berr_exit(FMT_NO_VERIFY);

  /*Check the cert chain. The chain length
    is automatically checked by OpenSSL when
    we set the verify depth in the ctx */
  
  peer = SSL_get_peer_certificate(ssl);
  X509_NAME_get_text_by_NID (X509_get_subject_name(peer), NID_commonName, peer_CN, 256);
  int NID_email = OBJ_txt2nid("emailAddress"); 
  X509_NAME_get_text_by_NID (X509_get_subject_name(peer), NID_email, peer_email, 256);  
  X509_NAME_get_text_by_NID (X509_get_issuer_name(peer), NID_commonName, peer_certificate_issuer, 256);

  /*Check the common name*/
  if(strcasecmp(peer_CN, SERVER_CN))
    err_exit(FMT_CN_MISMATCH);
    
  if(strcasecmp(peer_email, EMAIL))
    err_exit(FMT_EMAIL_MISMATCH);

  printf(FMT_SERVER_INFO, peer_CN, peer_email, peer_certificate_issuer);
}


int main(int argc, char **argv) {
  int sock, port=PORT;
  char *host = HOST;
  struct sockaddr_in addr;
  struct hostent *host_entry;
  char *secret = "What's the question?";
  
  /*Parse command line arguments*/
  
  switch(argc) {
    case 1:
      break;
    case 3:
      host = argv[1];
      port = atoi(argv[2]);
      if (port<1 || port>65535) {
        //err_exit("invalid port number\n");
        fprintf(stderr, "invalid port number");
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
  
  ctx = initialize_ctx(CLIENT_KEYFILE, CLIENT_PASSWORD, CA_LIST);
  
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
  SSL_CTX_set_cipher_list(ctx, "SHA1");  
  
  /*get ip address of the host ---TCP Connection---------------*/
  
  host_entry = gethostbyname(host);
  
  if (!host_entry) {
    err_exit("Couldn't resolve host\n");
  }

  memset(&addr,0,sizeof(addr));
  addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
  addr.sin_family=AF_INET;
  addr.sin_port=htons(port);
  
  printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);
  
  /*open socket*/
  
  if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0 ) {
    // if (close(sock)) {
    //   fprintf(stderr, "close\n");
    // }
    // err_exit("socket\n");
    perror("socket");
  }
    
  if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0) {
    // if (close(sock)) {
    //   fprintf(stderr, "close\n");
    // }
    // err_exit("connect\n");
    perror("connect");
  }

  /* Connect the SSL socket */
  ssl = SSL_new(ctx);
  sbio = BIO_new_socket(sock, BIO_NOCLOSE);
  SSL_set_bio(ssl, sbio, sbio);

  if(SSL_connect(ssl) <= 0) {
    // if (close(sock)) {
    //   fprintf(stderr, "close\n");
    // }
    berr_exit(FMT_CONNECT_ERR);
  }


  check_cert(ssl);
  // Wrap secret under SSL
  // if (send(sock, secret, strlen(secret), 0) != strlen(secret)) {
  //   err_exit(FMT_INCORRECT_CLOSE);
  // }
  // len = recv(sock, &buf, 255, 0);
  // buf[len]='\0';
  //printf("success cert check");
 
  
  int r;
  r = SSL_write(ssl, secret, strlen(secret));
  //printf("client write");
  switch(SSL_get_error(ssl,r)){
        case SSL_ERROR_NONE:
          if(strlen(secret) != r)
            err_exit("Incomplete write!");
          break;
        case SSL_ERROR_ZERO_RETURN:
          break;
        case SSL_ERROR_SYSCALL:
          berr_exit(FMT_INCORRECT_CLOSE);
          break;
        default:
          berr_exit("ECE568-CLIENT: SSL write problem\n");
  }

  char buf[BUFSIZE];
  int bytes_read;
  while(1) {
      r = SSL_read(ssl, buf, BUFSIZE);
      switch(SSL_get_error(ssl,r)) {
        case SSL_ERROR_NONE:
          bytes_read = r;
          goto success_read;
        case SSL_ERROR_ZERO_RETURN:
          goto shutdown;
        case SSL_ERROR_WANT_READ:
          continue;
        case SSL_ERROR_SYSCALL:
          berr_exit(FMT_INCORRECT_CLOSE);
          break;
        default:
          // fprintf(stderr, "ECE568-CLIENT: SSL read problem");
          // goto shutdown;
          berr_exit("ECE568-CLIENT: SSL read problem");
          break;
      }
  }
  
  success_read:
    /* this is how you output something for the marker to pick up */
    buf[bytes_read]='\0';
    printf(FMT_OUTPUT, secret, buf);
    //goto shutdown;

  shutdown:
    r = SSL_shutdown(ssl);
    if (!r) {
    //   /* If we called SSL_shutdown() first then
    //       we always get return value of '0'. In
    //       this case, try again, but first send a
    //       TCP FIN to trigger the other side's
    //       close_notify*/
      shutdown(sock, 1);
      r = SSL_shutdown(ssl);
    }   
    switch(r){  
      case 1:
        break; /* Success */
      case 0:
        break;
      case -1:
        break;
      default:
        printf("Shutdown ssl failed\n");
    }

  // done:
    SSL_free(ssl);
    
    destroy_ctx(ctx);
    close(sock);
    // if (close(sock)) {
    //   err_exit("close\n");
    // }
    return 1;
          
  }
  