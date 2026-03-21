#include "ucspissl.h"
#include "iopause.h"
#include "logmsg.h"

#define WHO "ssl_timeout"

int ssl_timeoutaccept(SSL *ssl,unsigned int timeout)
{
  struct taia now;
  struct taia deadline;
  iopause_fd x;
  int r;
  int rfd;
  int wfd;

  if (taia_now(&now) == -1) {
    errno = ETIMEDOUT;
    return -1;
  }
  taia_uint(&deadline,timeout);
  taia_add(&deadline,&now,&deadline);

  rfd = SSL_get_fd(ssl); /* XXX */
  wfd = SSL_get_fd(ssl); /* XXX */

  SSL_set_accept_state(ssl);

  for (;;) {
    r = SSL_accept(ssl);
    if (r == 1) return 0;
    ssl_errno = SSL_get_error(ssl,r);
    errno = EPROTO;
    if ((ssl_errno != SSL_ERROR_WANT_READ) && (ssl_errno != SSL_ERROR_WANT_WRITE))
      return -1;
    if (ssl_errno == SSL_ERROR_WANT_READ) {
      x.events = IOPAUSE_READ;
      x.fd = rfd;
      if (x.fd == -1) return -1;
    }
    else {
      x.events = IOPAUSE_WRITE;
      x.fd = wfd;
      if (x.fd == -1) return -1;
    }
    for (;;) {
      if (taia_now(&now) == -1) {
			  errno = ETIMEDOUT;
				return -1;
			}
      iopause(&x,1,&deadline,&now);
      if (x.revents) break;
      if (taia_less(&deadline,&now)) {
        errno = ETIMEDOUT;
        return -1;
      }
    }
  }
}

int ssl_timeoutconn(SSL *ssl,unsigned int timeout)
{
  struct taia now;
  struct taia deadline;
  iopause_fd x;
  int r;
  int rfd;
  int wfd;

  taia_now(&now);
  taia_uint(&deadline,timeout);
  taia_add(&deadline,&now,&deadline);

  rfd = SSL_get_fd(ssl); /* XXX */
  wfd = SSL_get_fd(ssl); /* XXX */

  SSL_set_connect_state(ssl);

  for (;;) {
    r = SSL_connect(ssl);
    errno = EPROTO;
    if (r == 1) return 0;
    ssl_errno = SSL_get_error(ssl,r);
    if ((ssl_errno != SSL_ERROR_WANT_READ) && (ssl_errno != SSL_ERROR_WANT_WRITE))
      return -1;
    if (ssl_errno == SSL_ERROR_WANT_READ) {
      x.events = IOPAUSE_READ;
      x.fd = rfd;
      if (x.fd == -1) return -1;
    }
    else {
      x.events = IOPAUSE_WRITE;
      x.fd = wfd;
      if (x.fd == -1) return -1;
    }
    for (;;) {
      if (taia_now(&now) == -1) {
			  errno = ETIMEDOUT;
				return -1;
			}
      iopause(&x,1,&deadline,&now);
      if (x.revents) break;
      if (taia_less(&deadline,&now)) {
        errno = ETIMEDOUT;
        return -1;
      }
    }
  }
}

stralloc sslerror = {0};

int ssl_verberror(void) 
{ 
   char buf[256]; 
   unsigned long err; 
   
   if (!stralloc_copys(&sslerror,"")) return -1;

   while ((err = ERR_get_error()) != 0) { 
     ERR_error_string_n(err,buf,sizeof(buf)); 
     if (!stralloc_cats(&sslerror,buf)) return -1;
     if (!stralloc_cats(&sslerror," ")) return -1;
   } 
   return err;
} 
