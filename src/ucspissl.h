/** 
  @file ucspissl.h
  @author web, feh
  @brief Header file to be used with sqmail; previously called ssl.h. (name clash)

  All OpenSSL/LibreSSL header files are called from here
*/
#ifndef UCSPISSL_H
#define UCSPISSL_H

#include <openssl/ssl.h>
/* the version is like this: 0xMNNFFPPS: major minor fix patch status */
#if OPENSSL_VERSION_NUMBER < 0x10101000L
# error "Need OpenSSL version at least 1.1.1"
#endif
#include "openssl/asn1.h"
#include "openssl/ec.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/ssl.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"
#include "openssl/opensslv.h"
#include "openssl/safestack.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"
#include "stralloc.h"

#define SSLv2_DISABLE
#define SSLv3_DISABLE
// #define TLSv1_DISABLE
// #define TLSv1_1_DISABLE
// #define TLSv1_2_DISABLE
// #define TLSv1_3_DISABLE

#define SSL_NAME_LEN 256
#define SSL_RSA_LEN 4096

#define ssl_client() (ssl_context(TLS_client_method()))
#define ssl_server() (ssl_context(TLS_server_method()))

extern int ssl_errno;
extern int ssl_io(SSL *,int,int,unsigned int);
extern SSL_CTX *ssl_context(const SSL_METHOD *);
extern int ssl_timeoutconn(SSL *,unsigned int);
extern int ssl_timeoutaccept(SSL *,unsigned int);
extern SSL *ssl_new(SSL_CTX *,int);
extern int ssl_certkey(SSL_CTX *,const char *,const char *,pem_password_cb *);
extern int ssl_chainfile(SSL_CTX *,const char *,const char *,pem_password_cb *);
extern int ssl_ca(SSL_CTX *,const char *,const char *,int);
extern int ssl_cca(SSL_CTX *,const char *);
extern int ssl_ciphers(SSL_CTX *,const char *);
extern int ssl_verify(SSL *,const char *,stralloc *);
extern int ssl_params_rsa(SSL_CTX *,int);
extern int ssl_params_dh(SSL_CTX *,const char *);
extern int ssl_server_env(SSL *,stralloc *);
extern int ssl_client_env(SSL *,stralloc *);
extern int ssl_error(int (*)(const char *));
extern char *ssl_error_str(int);

#define ssl_errstr() (SSL_load_error_strings())
#define ssl_free(ssl) (SSL_free((ssl)))
#define ssl_close(ssl) (close(SSL_get_fd((ssl))))

#define ssl_pending(ssl) (SSL_pending((ssl)))
#define ssl_shutdown(ssl) (SSL_shutdown((ssl)))
#define ssl_shutdown_pending(ssl) (SSL_get_shutdown((ssl)) & SSL_RECEIVED_SHUTDOWN)
#define ssl_shutdown_sent(ssl) (SSL_get_shutdown((ssl)) & SSL_SENT_SHUTDOWN)

#endif
