//reference: https://aticleworld.com/ssl-server-client-using-openssl-in-c/
//https://github.com/Andersbakken/openssl-examples/blob/master/part1.pdf

#include "common.h"

BIO *bio_err = NULL;

static char *pass;
static int password_cb(char *buf, int num, int rwflag, void *userdata);
static void sigpipe_handle(int x);

/* A simple error and exit routine*/
void err_exit(char *string) {
  fprintf(stderr, "%s", string);
}

/* Print SSL errors and exit*/
void berr_exit(char *string) {
  BIO_printf(bio_err, "%s", string);
  ERR_print_errors(bio_err);
}

/*The password code is not thread safe*/
static int password_cb(char *buf,int num, int rwflag,void *userdata) {
  if(num<strlen(pass)+1) return(0);

  strcpy(buf,pass);
  return(strlen(pass));
}

static void sigpipe_handle(int x){

}

//context initialization
SSL_CTX *initialize_ctx(char *keyfile, char *password, char *CA_LIST) {
    const SSL_METHOD *meth;
    SSL_CTX *ctx;
    if (!bio_err) {
      /* Global system initialization*/
      SSL_library_init();  //load up algorithms OpenSSL will be using
      SSL_load_error_strings();  //report of errors

      /* An error write context */
      bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);  //BIO object fir input and output
    }

    /* Set up a SIGPIPE handler */
    signal(SIGPIPE,sigpipe_handle);

    /* Create our context*/
    meth = SSLv23_method();
    ctx = SSL_CTX_new( (const SSL_METHOD *) meth);

    /* Load our keys and certificates*/
    if(!(SSL_CTX_use_certificate_chain_file(ctx, keyfile)))
      berr_exit("Can't read certificate file");
    pass=password;

    /*private key is usually encrypted.under a password, call password callback
    if the key is encrypted in order to obtain the password*/
    SSL_CTX_set_default_passwd_cb(ctx, password_cb);
    if(!(SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM)))
      berr_exit("Can't read key file");

    /* Load the CAs we trust*/
    if(!(SSL_CTX_load_verify_locations(ctx, CA_LIST,0)))
      berr_exit("Can't read CA list");
    #if (OPENSSL_VERSION_NUMBER < 0x00905100L)
        SSL_CTX_set_verify_depth(ctx,1);
    #endif

    return ctx;
  }


void destroy_ctx(SSL_CTX *ctx) {
  SSL_CTX_free(ctx);
}
