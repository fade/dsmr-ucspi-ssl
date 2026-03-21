#include "ucspissl.h"

int ssl_ciphers(SSL_CTX *ctx,const char *ciphers) {
  int r = 0;  // no cipher selected

  if (!ciphers) return -1;

/* TLS <= 1.2		SSL_CTX_set_cipher_list()	
   TLS  = 1.3		SSL_CTX_set_ciphersuites() [only OpenSSL here]

   see: https://community.openvpn.net/openvpn/ticket/1159
*/
  r = SSL_CTX_set_ciphersuites(ctx,ciphers);
  
  return r;  
}

