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

#define SERVER_KEYFILE "bob.pem"
#define SERVER_PASSWORD "password"

#define CIPHERS "SSLv2:SSLv3:TLSv1"

#define BUFSIZE 256

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"


int check_cert(SSL *ssl) {
  X509 *peer;
  char peer_CN[256];
  char peer_email[256];

  if (SSL_get_verify_result(ssl) != X509_V_OK) {
    berr_exit(FMT_ACCEPT_ERR);
    return 1;
  }
    

  /*Check the cert chain. The chain length
    is automatically checked by OpenSSL when
    we set the verify depth in the ctx */

  
  peer = SSL_get_peer_certificate(ssl);
  X509_NAME_get_text_by_NID (X509_get_subject_name(peer), NID_commonName, peer_CN, 256);
  int NID_email = OBJ_txt2nid("emailAddress"); 
  X509_NAME_get_text_by_NID (X509_get_subject_name(peer), NID_email, peer_email, 256);  

  printf(FMT_CLIENT_INFO, peer_CN, peer_email);
  return 0;
}


int main(int argc, char **argv) {

  int s, sock, port=PORT;
  struct sockaddr_in sin;
  int val=1;
  pid_t pid;
  
  /*Parse command line arguments*/
  switch(argc) {
    case 1:
      break;
    case 2:
      port=atoi( argv[1] );
      if ( port<1 || port > 65535 ) {
        err_exit("invalid port number\n");
        exit(0);
      }
      break;
    default:
      printf("Usage: %s port\n", argv[0]);
      exit(0);
  }

  /*Initialize SSL*/
  SSL_CTX *ctx = initialize_ctx(SERVER_KEYFILE, SERVER_PASSWORD, CA_LIST);

  SSL_CTX_set_cipher_list(ctx, CIPHERS); //suport SSLv2, SSLv3, TLSv1
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);

  /*TCP Connection*/
  if ((sock=socket(AF_INET,SOCK_STREAM,0))<0) {
    perror("socket");
    close(sock);
    exit(0);
  }
  
  memset(&sin, 0, sizeof(sin));
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_family = AF_INET;
  sin.sin_port = htons(port);
  
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

  if(bind(sock,(struct sockaddr *)&sin, sizeof(sin))<0) {
    perror("bind");
    close(sock);
    exit (0);
  }
  
  if(listen(sock,5) < 0) {
    perror("listen");
    close(sock);
    exit (0);
  }

  // server handling requests
  while(1) {
    if((s=accept(sock, NULL, 0))<0) {
      perror("accept");
      close(sock);
      close(s);
      exit (0);
    }
    
    /*fork a child to handle the connection*/
    
    if((pid=fork())){
      close(s);
    } 
    else {
      /*Child code*/
      SSL *ssl;
      BIO *sbio;
      // Set up SSL logic
      sbio = BIO_new_socket(s, BIO_NOCLOSE);
      ssl = SSL_new(ctx);
      //  void SSL_set_bio(SSL *ssl, BIO *rbio, BIO *wbio);
      SSL_set_bio(ssl, sbio, sbio);
      
      if( SSL_accept(ssl) <= 0 ) {
        berr_exit(FMT_ACCEPT_ERR);
        goto shutdown;
      }

      // check ssl certificate
      if (check_cert(ssl)) {
        goto shutdown;
      }

      // len = recv(s, &buf, 255, 0);
      int r, bytes_read;
      char buf[256];
      char *answer = "42";
      // while(1) {
      r = SSL_read(ssl, buf, BUFSIZE);
      switch(SSL_get_error(ssl,r)) {
        case SSL_ERROR_NONE:
          bytes_read = r;
          buf[bytes_read] = '\0';
          goto success_read;
          break;
        case SSL_ERROR_WANT_READ:
          continue;
        case SSL_ERROR_SYSCALL:
          berr_exit(FMT_INCOMPLETE_CLOSE);
          goto shutdown;
          break;
        default:
          berr_exit("ECE568-SERVER: SSL read problem");
          goto shutdown;
      }

      success_read:
        printf(FMT_OUTPUT, buf, answer);
        r = SSL_write(ssl, answer, strlen(answer));
        switch(SSL_get_error(ssl,r)){
          case SSL_ERROR_NONE:
            if(strlen(answer) != r)
              err_exit("Incomplete write!");
            break;
          case SSL_ERROR_ZERO_RETURN:
            break;
          case SSL_ERROR_SYSCALL:
            berr_exit(FMT_INCOMPLETE_CLOSE);
            break;
          default:
            berr_exit("ECE568-SERVER: SSL write problem\n");
            break;
        }
        goto shutdown;
      
      shutdown:
        r = SSL_shutdown(ssl);
        if (!r) {
          /* If we called SSL_shutdown() first then
              we always get return value of '0'. In
              this case, try again, but first send a
              TCP FIN to trigger the other side's
              close_notify*/
          shutdown(s, 1);
          r = SSL_shutdown(ssl);
        }
          
        switch(r){  
          case 1:
            break; /* Success */
          case 0:
          case -1:
          default:
            printf(FMT_INCOMPLETE_CLOSE);
        }

        SSL_free(ssl);
        exit(0);
        // out of while loop
        destroy_ctx(ctx);
        if (close(s)) {
          err_exit("close\n");
        }
        return 0;
    }
    
  }

}
