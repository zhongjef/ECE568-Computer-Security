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
#define SERVER_KEYFILE "bob.pem"
#define SERVER_PASSWORD "password"
#define CA_LIST "568ca.pem"
#define CIPHERS "SSLv2:SSLv3:TLSv1"
#define BUFSIZE 256

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"

int main(int argc, char **argv) {
  int s, sock, port=PORT;
  struct sockaddr_in sin;
  int val=1;
  pid_t pid;
  
  /*Parse command line arguments*/
  switch(argc){
    case 1:
      break;
    case 2:
      port=atoi( argv[1] );
      if ( port<1 || port > 65535 ) {
        fprintf(stderr,"invalid port number");
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

  /*TCP Connection*/
  if ((sock=socket(AF_INET,SOCK_STREAM,0))<0) {
    perror("socket");
    close(sock);
    exit(0);
  }
  
  memset(&sin,0,sizeof(sin));
  sin.sin_addr.s_addr=INADDR_ANY;
  sin.sin_family=AF_INET;
  sin.sin_port=htons(port);
  
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val,sizeof(val));

  if(bind(sock,(struct sockaddr *)&sin, sizeof(sin))<0){
    perror("bind");
    close(sock);
    exit (0);
  }
  
  if(listen(sock,5) < 0) {
    perror("listen");
    close(sock);
    exit (0);
  }

  SSL *ssl;
  BIO *sbio;
  // server handling requests
  while(1){
    if((s=accept(sock, NULL, 0))<0){
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
      // Set up SSL logic
      int len;
      char buf[256];
      char *answer = "42";

      sbio = BIO_new_socket(s, BIO_NOCLOSE);
      ssl = SSL_new(ctx);
      //  void SSL_set_bio(SSL *ssl, BIO *rbio, BIO *wbio);
      SSL_set_bio(ssl, sbio, sbio);
      
      if( SSL_accept(ssl) <= 0 ) {
        berr_exit(FMT_ACCEPT_ERR);
        ERR_print_errors(sbio);
      }
        

      // check ssl certificate
      SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);

      len = recv(s, &buf, 255, 0);
      buf[len]= '\0';
      printf(FMT_OUTPUT, buf, answer);
      send(s, answer, strlen(answer), 0);
      close(sock);
      close(s);
      return 0;
    }
  }
  
  // out of while loop
  destroy_ctx(ctx);
  close(sock);
  return 1;
}
