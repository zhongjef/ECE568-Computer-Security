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

#define PORT 5555
#define SERVER_KEYFILE "bob.pem"
#define SERVER_PASSWORD "password"
#define CIPHERS "SSLv2:SSLv3:TLSv1"
#define BUFSIZE 256

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"

static int http_serve(SSL *ssl, int s) {
    char buf[BUFSIZE];
    int r,len;
    BIO *io, *ssl_bio;
    
    io=BIO_new(BIO_f_buffer());
    ssl_bio=BIO_new(BIO_f_ssl());
    BIO_set_ssl(ssl_bio,ssl,BIO_CLOSE);
    BIO_push(io,ssl_bio);
    
    while(1){
      r=BIO_gets(io,buf,BUFSIZE-1);

      switch(SSL_get_error(ssl,r)){
        case SSL_ERROR_NONE:
          len=r;
          break;
        default:
          berr_exit("SSL read problem");
      }

      /* Look for the blank line that signals
         the end of the HTTP headers */
      if (!strcmp(buf,"\r\n") || !strcmp(buf,"\n"))
        break;
    }

    if((r=BIO_puts(io,"HTTP/1.0 200 OK\r\n"))<=0)
      err_exit("Write error");
    if((r=BIO_puts(io,"Server: EKRServer\r\n\r\n"))<=0)
      err_exit("Write error");
    if((r=BIO_puts(io,"Server test page\r\n"))<=0)
      err_exit("Write error");
    
    if((r=BIO_flush(io))<0)
      err_exit("Error flushing BIO");


    
    r = SSL_shutdown(ssl);
    if (!r) {
      /* If we called SSL_shutdown() first then
         we always get return value of '0'. In
         this case, try again, but first send a
         TCP FIN to trigger the other side's
         close_notify*/
      shutdown(s,1);
      r=SSL_shutdown(ssl);
    }

    switch(r){  
      case 1:
        break; /* Success */
      case 0:
      case -1:
      default:
        berr_exit("Shutdown failed");
    }

    SSL_free(ssl);
    close(s);

    return(0);
}

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
  SSL_CTX *ctx = initialize_ctx(SERVER_KEYFILE, SERVER_PASSWORD);

  SSL_CTX_set_cipher_list(ctx, CIPHERS); //suport SSLv2, SSLv3, TLSv1



  if ((sock=socket(AF_INET,SOCK_STREAM,0))<0) {
    perror("socket");
    close(sock);
    exit(0);
  }
  
  memset(&sin,0,sizeof(sin));
  sin.sin_addr.s_addr=INADDR_ANY;
  sin.sin_family=AF_INET;
  sin.sin_port=htons(port);
  
  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR, &val,sizeof(val));
    
  if(bind(sock,(struct sockaddr *)&sin, sizeof(sin))<0){
    perror("bind");
    close(sock);
    exit (0);
  }
  
  if(listen(sock,5)<0){
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
      int len;
      char buf[256];
      char *answer = "42";

      sbio=BIO_new_socket(s, BIO_NOCLOSE);
      ssl=SSL_new(ctx);
      SSL_set_bio(ssl, sbio, sbio);
      
      if( SSL_accept(ssl) <= 0 )
        berr_exit(FMT_ACCEPT_ERR);
      
      http_serve(ssl,s);

      len = recv(s, &buf, 255, 0);
      buf[len]= '\0';
      printf(FMT_OUTPUT, buf, answer);
      send(s, answer, strlen(answer), 0);
      close(sock);
      close(s);
      return 0;
    }
  }
  
  destroy_ctx(ctx);
  close(sock);
  return 1;
}
