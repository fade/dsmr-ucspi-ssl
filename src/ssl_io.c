#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "iopause.h"
#include "buffer.h"
#include "taia.h"
#include "ucspissl.h"
#include "error.h"

static int leftstatus = 0;
static char leftbuf[16 * 1024];
static int leftlen;
static int leftpos;

static int rightstatus = 0;
static char rightbuf[16 * 1024];
static int rightlen;
static int rightpos;

int ssl_io(SSL *ssl,int fdleft,int fdright,unsigned int timeout) {
  struct taia now;
  struct taia deadline;
  iopause_fd x[4];
  int xlen;
  iopause_fd *io0;
  iopause_fd *ioleft;
  iopause_fd *io1;
  iopause_fd *ioright;
  int r;
  int rc = 0;
  int rfd;
  int wfd;

  rfd = SSL_get_fd(ssl); /* XXX */
  if (rfd == -1) {
    close(fdleft); close(fdright);
    return -1;
  }
  wfd = SSL_get_fd(ssl); /* XXX */
  if (wfd == -1) {
    close(fdleft); close(fdright);
    return -1;
  }

  for (;;) {
    xlen = 0;

    if (leftstatus == -1 && rightstatus == -1)
      goto DONE;

    io0 = 0;
    if (leftstatus == 0 && rightstatus != 1) {
      io0 = &x[xlen++];
      io0->fd = rfd;
      io0->events = IOPAUSE_READ;
    }

    ioleft = 0;
    if (leftstatus == 1) {
      ioleft = &x[xlen++];
      ioleft->fd = fdleft;
      ioleft->events = IOPAUSE_WRITE;
    }

    ioright = 0;
    if (rightstatus == 0) {
      ioright = &x[xlen++];
      ioright->fd = fdright;
      ioright->events = IOPAUSE_READ;
    }

    io1 = 0;
    if (rightstatus == 1) {
      io1 = &x[xlen++];
      io1->fd = wfd;
      io1->events = IOPAUSE_WRITE;
    }

    if (taia_now(&now) == -1) {
      errno = ETIMEDOUT;
      rc = -1;
      goto BOMB;
    }
    taia_uint(&deadline,timeout);
    taia_add(&deadline,&now,&deadline);
    iopause(x,xlen,&deadline,&now); 

    for (r = 0; r < xlen; ++r)
      if (x[r].revents) goto EVENTS;
    
    if (io0 && !ssl_pending(ssl)) {
      close(fdleft);
      leftstatus = -1;
      continue;
    }
    errno = ETIMEDOUT;
    rc = -1;
    goto BOMB;


EVENTS:
    if (io0 && io0->revents) {
      r = SSL_read(ssl,leftbuf,sizeof(leftbuf));
      ssl_errno = SSL_get_error(ssl,r);
      switch (ssl_errno) {
        case SSL_ERROR_NONE:
        leftstatus = 1;
        leftpos = 0;
        leftlen = r;
        break;
      case SSL_ERROR_WANT_READ:
      case SSL_ERROR_WANT_WRITE:
      case SSL_ERROR_WANT_X509_LOOKUP:
        break;
      case SSL_ERROR_ZERO_RETURN:
        if (rightstatus == -1) goto DONE;
        close(fdleft);
        leftstatus = -1;
        break;
      case SSL_ERROR_SYSCALL:
        if (errno == EAGAIN || errno == EINTR) break;
        close(fdleft);
        leftstatus = -1;
        if (!errno) break;
	  /* premature close */
        if (errno == ECONNRESET && rightstatus == -1) goto DONE;
        goto BOMB;
      case SSL_ERROR_SSL:
/* Continuing after a received SSL error given the socket is still 
 * potentially active might be a noble cause, but is impracticle.
 * We consider an SSL_ERROR_SSL as application failure; not TLS
 * and close the connection gracefully.
 *        if (errno == EAGAIN || errno == EINTR) break;
 *        if (!errno) break;
 */
        goto DONE;
      default:
        close(fdleft);
        leftstatus = -1;
        if (rightstatus == 1) break;
        if (ssl_shutdown_pending(ssl)) goto DONE;
        goto BOMB;
      }
    } 

    if (ioleft && ioleft->revents) {
      r = buffer_unixwrite(fdleft,leftbuf + leftpos,leftlen - leftpos);
      if (r == -1) {
        if (errno == EINTR || errno == EWOULDBLOCK) {
	  /* retry */
	}
      else if (errno == EPIPE || errno == EAGAIN) {
        if (rightstatus == -1) goto DONE;
        close(fdleft);
        leftstatus = -1;
      } else {
        rc = -1;
        goto BOMB;
        }
      }
      else {
        leftpos += r;
        if (leftpos == leftlen) {
          leftstatus = 0;
          if ((r = ssl_pending(ssl))) {
            if (r > sizeof(leftbuf)) r = sizeof(leftbuf);
            r = SSL_read(ssl,leftbuf,r);
            ssl_errno = SSL_get_error(ssl,r);
            switch (ssl_errno) {
              case SSL_ERROR_NONE:
                leftstatus = 1;
                leftpos = 0;
                leftlen = r;
                break;
              case SSL_ERROR_WANT_READ:
              case SSL_ERROR_WANT_WRITE:
              case SSL_ERROR_WANT_X509_LOOKUP:
                break;
              case SSL_ERROR_ZERO_RETURN:
                if (rightstatus == -1) goto DONE;
                close(fdleft);
                leftstatus = -1;
                break;
              default:
                rc = -1;
                goto BOMB;
            }
          }
        }
      }
    }

    if (ioright && ioright->revents) {
      r = buffer_unixread(fdright,rightbuf,sizeof(rightbuf));
      if (r == -1) {
        if (errno == EINTR || errno == EWOULDBLOCK) {
	  /* retry */
        } else {
          rc = -1;
          goto BOMB;  /* errno == EAGAIN => unrecoverable */
        }
      }
      else if (r == 0) {
        close(fdright);
        rightstatus = -1;
        if (ssl_shutdown(ssl)) goto DONE; 
        if (leftstatus == -1) goto DONE;
      }
      else {
        rightstatus = 1;
        rightpos = 0;
        rightlen = r;
      }
    }

    if (io1 && io1->revents) {
      r = SSL_write(ssl,rightbuf + rightpos,rightlen - rightpos);
      ssl_errno = SSL_get_error(ssl,r);
      switch (ssl_errno) {
        case SSL_ERROR_NONE:
          rightpos += r;
          if (rightpos == rightlen) rightstatus = 0;
          break;
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_X509_LOOKUP:
          break;
        case SSL_ERROR_ZERO_RETURN:
          close(fdright);
          rightstatus = -1;
          if (leftstatus == -1) goto DONE;
          if (ssl_shutdown(ssl)) goto DONE;
          break;
        case SSL_ERROR_SYSCALL:
          if (errno == EAGAIN || errno == EINTR) break;
          if (errno == EPIPE) {
            close(fdright);
            rightstatus = -1;
            if (leftstatus == -1) goto DONE;
            if (ssl_shutdown(ssl)) goto DONE;
            break;
          }
        default:
          rc = -1;
          goto BOMB;
      }
    }
  }


BOMB:
  r = errno;
  if (leftstatus != -1) close(fdleft);
  if (rightstatus != -1) close(fdright);
  if (!ssl_shutdown_sent(ssl)) ssl_shutdown(ssl);
  if (!ssl_shutdown_pending(ssl)) ssl_shutdown(ssl);
  shutdown(wfd,2);
  errno = r;
  return rc;


DONE:
  if (!ssl_shutdown_sent(ssl)) ssl_shutdown(ssl);
  if (!ssl_shutdown_pending(ssl)) ssl_shutdown(ssl);
  shutdown(wfd,2);
  if (leftstatus != -1) close(fdleft);
  if (rightstatus != -1) close(fdright);
  return 0;
}
