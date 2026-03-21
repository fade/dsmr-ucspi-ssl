/** 
  @file  sslclient.c
  @author web, fefe, feh
  @brief IPv6 enabled sslclient
*/
#include <unistd.h>
#include <open.h>
#include <sys/types.h>
#include <sys/param.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "ucspissl.h"
#include "sig.h"
#include "exit.h"
#include "getoptb.h"
#include "uint_t.h"
#include "fmt.h"
#include "scan.h"
#include "str.h"
#include "ip.h"
#include "socket_if.h"
#include "fd.h"
#include "stralloc.h"
#include "buffer.h"
#include "getln.h"
#include "logmsg.h"
#include "pathexec.h"
#include "timeoutconn.h"
#include "remoteinfo.h"
#include "dnsresolv.h"
#include "byte.h"
#include "ndelay.h"
#include "wait.h"
#include "auto_cafile.h"
#include "auto_cadir.h"
#include "auto_ciphers.h"

#define WHO "sslclient"

void nomem(void) {
  logmsg(WHO,111,FATAL,"out of memory");
}
void env(const char *s,const char *t) {
  if (!pathexec_env(s,t)) nomem();
}

void usage(void) {
  logmsg(WHO,100,USAGE,"sslclient \
[ -463hHrRdDiqQveEsSnNxX ] \
[ -i localip ] \
[ -p localport ] \
[ -T timeoutconn ] \
[ -l localname ] \
[ -t timeoutinfo ] \
[ -I interface ] \
[ -a cafile ] \
[ -A cadir ] \
[ -c certfile ] \
[ -z ciphers ] \
[ -k keyfile ] \
[ -K keypassfile ] \
[ -V verifydepth ] \
[ -w progtimeout ] \
host port program");
}

int verbosity = 1;
int flagdelay = 0;
int flagremoteinfo = 0;
int flagremotehost = 1;
int flag3 = 0;
int flagsslenv = 0;
int flagtcpenv = 0;
int flagsni = 0;
unsigned long itimeout = 26;
unsigned long ctimeout[2] = { 2, 58 };
unsigned int progtimeout = 3600;
uint32 netif = 0;

const char *loopback = "127.0.0.1";
char iplocal[16] = { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 };
uint16 portlocal = 0;
const char *forcelocal = 0;

char ipremote[16];
uint16 portremote;

const char *hostname;
int flagname = 1;
int flagservercert = 1;
static stralloc addresses;
static stralloc certname;
static stralloc moreaddresses;

static stralloc tmp;
static stralloc fqdn;
static char strnum[FMT_ULONG];
static char ipstr[IP6_FMT];

char seed[128];

char bspace[16];
buffer b;

SSL_CTX *ctx;
const char *certfile = 0;
const char *keyfile = 0;
const char *keypass = 0;
const char *cafile = auto_cafile;
const char *cadir = auto_cadir;
const char *ciphers = auto_ciphers;
stralloc password = {0};
int match = 0;
int verifydepth = 1;

int pi[2];
int po[2];
int pt[2];

void read_pwdfile()
{
  int fd;
  
  if (!password.len) {
    fd = open_read(keypass);
    if (fd == -1) 
      logmsg(WHO,111,ERROR,B("unable to read password from: ",keypass));

    buffer_init(&b,buffer_unixread,fd,bspace,sizeof(bspace));
    if (getln(&b,&password,&match,'\0') == -1)
      logmsg(WHO,111,ERROR,B("unable to read password from: ",keypass));
    close(fd);
    if (match) --password.len;
  }
}

void read_passwd() {
  if (!password.len) {
    buffer_init(&b,buffer_unixread,3,bspace,sizeof(bspace));
    if (getln(&b,&password,&match,'\0') == -1)
      logmsg(WHO,111,ERROR,"unable to read password from FD3");
    close(3);
    if (match) --password.len;
  }
}

int passwd_cb(char *buf,int size,int rwflag,void *userdata) {
  if (size < password.len)
    logmsg(WHO,111,ERROR,"password too long");

  byte_copy(buf,password.len,password.s);
  return password.len;
}

int main(int argc,char * const argv[]) 
{
  unsigned long u;
  int opt;
  const char *x;
  int j;
  int s;
  int r;
  int cloop;
  SSL *ssl;
  int wstat;
  int ipflag = 0;

  dns_random_init(seed);

  close(6);
  close(7);
  sig_ignore(sig_pipe);
 
  while ((opt = getoptb(argc,(char **)argv,"dDvqQhHrRimM:p:t:T:l:a:A:c:z:k:K:V:346eEsSnN0xXw:")) != opteof)
    switch(opt) {
      case '4': ipflag = 1; break;
      case '6': ipflag = 0; break;
      case 'd': flagdelay = 1; break;
      case 'D': flagdelay = 0; break;
      case 'm': flagsni = 1; break;
      case 'M': flagsni = 0; break;
      case 'v': verbosity = 2; break;
      case 'q': verbosity = 0; break;
      case 'Q': verbosity = 1; break;
      case 'l': forcelocal = optarg; break;
      case 'H': flagremotehost = 0; break;
      case 'h': flagremotehost = 1; break;
      case 'R': flagremoteinfo = 0; break;
      case 'r': flagremoteinfo = 1; break;
      case 't': scan_ulong(optarg,&itimeout); break;
      case 'T': j = scan_ulong(optarg,&ctimeout[0]);
                if (optarg[j] == '+') ++j;
                scan_ulong(optarg + j,&ctimeout[1]); break;
      case 'w': scan_uint(optarg,&progtimeout); break;
      case 'i': if (!ip6_scan(optarg,iplocal)) usage(); break;
      case 'I': netif = socket_getifidx(optarg); break;
      case 'p': scan_ulong(optarg,&u); portlocal = u; break;
      case 'a': cafile = optarg; break;
      case 'A': cadir = optarg; break;
      case 'c': certfile = optarg; break;
      case 'z': ciphers = optarg; break;
      case 'k': keyfile = optarg; break;
      case 'K': keypass = optarg; break;
      case 'V': scan_ulong(optarg,&u); verifydepth = u; break;
      case '3': flag3 = 1; break;
      case 'S': flagsslenv = 0; break;
      case 's': flagsslenv = 1; break;
      case 'E': flagtcpenv = 0; break;
      case 'e': flagtcpenv = 1; break;
      case 'N': flagname = 0; break;
      case 'n': flagname = 1; break;
      case 'x': flagservercert = 1; break;
      case 'X': flagservercert = 0; break;
      default: usage();
    }
  argv += optind;

  if (!verbosity)
    buffer_2->fd = -1;

  hostname = *argv;
  if (!hostname || str_equal((char *)hostname,"")) usage();
  if (str_equal((char *)hostname,"0")) hostname = loopback;

  x = *++argv;
  if (!x) usage();
  if (!x[scan_ulong(x,&u)])
    portremote = u;
  else {
    struct servent *se;
    se = getservbyname(x,"tcp");
    if (!se)
      logmsg(WHO,111,FATAL,B("unable to figure out port number for ",x));
    uint16_unpack_big((char*)&se->s_port,&portremote);
  }

  if (flag3) read_passwd();
  if (keypass) read_pwdfile();

  if (cafile && str_equal(cafile,"")) cafile = 0;
  if (cadir && str_equal(cadir,"")) cadir= 0;
  if (ciphers && str_equal(ciphers,"")) ciphers= 0;

  if (certfile && str_equal(certfile,"")) certfile = 0;
  if (keyfile && str_equal(keyfile,"")) keyfile = 0;
  if (keypass && str_equal(keypass,"")) keypass = 0;

  if (!*++argv) usage();

  /* IP address only */

  if (ip4_scan(hostname,ipremote)) {
    if (!stralloc_copyb(&addresses,(char *)V4mappedprefix,12)) nomem();
    if (!stralloc_catb(&addresses,ipremote,4)) nomem();
    byte_copy(iplocal,16,addresses.s);
  } else if (ip6_scan(hostname,ipremote)) {
      if (!stralloc_copyb(&addresses,ipremote,16)) nomem();
      byte_copy(iplocal,16,addresses.s);
  }

  if (addresses.len < 4) {
    if (!stralloc_copys(&tmp,hostname)) nomem();
    dns_ip_qualify(&addresses,&fqdn,&tmp);
    if (addresses.len < 16) 
      logmsg(WHO,111,ERROR,B("No IP address for: ",hostname));
  }

  if (addresses.len == 16) {
     ctimeout[0] += ctimeout[1];
     ctimeout[1] = 0;
  }

  for (cloop = 0; cloop < 2; ++cloop) {
    if (!stralloc_copys(&moreaddresses,"")) nomem();
    for (j = 0; j + 16 <= addresses.len; j += 16) {
      if (ipflag == 1 || ip6_isv4mapped(addresses.s + j)) {
        s = socket_tcp4();
        if (s == -1) logmsg(WHO,111,FATAL,"unable to create socket");
        r = socket_bind4(s,iplocal,portlocal);
      } else {
        s = socket_tcp6();
        if (s == -1) logmsg(WHO,111,FATAL,"unable to create socket");
        r = socket_bind6(s,iplocal,portlocal,netif);
      }   
      strnum[fmt_ulong(strnum,portlocal)] = 0;
      if (r == -1) logmsg(WHO,111,FATAL,B("unable to bind to socket for local port: ",strnum));
      if (timeoutconn(s,addresses.s + j,portremote,ctimeout[cloop],netif) == 0)
        goto CONNECTED;
      close(s);
      if (!cloop && ctimeout[1] && (errno == ETIMEDOUT)) {
        if (!stralloc_catb(&moreaddresses,addresses.s + j,16)) nomem();
      }   
      else {
        strnum[fmt_ulong(strnum,portremote)] = 0;
        if (ip6_isv4mapped(addresses.s + j)) 
          ipstr[ip4_fmt(ipstr,addresses.s + j + 12)] = 0;
        else
          ipstr[ip6_fmt(ipstr,addresses.s + j)] = 0;
      }   
    }   
    if (!stralloc_copy(&addresses,&moreaddresses)) nomem();
  }
  logmsg(WHO,110,DROP,B("unable to connect to: ",ipstr," port: ",strnum));

  _exit(111);

  CONNECTED:

  /* Local */

  if (socket_local(s,iplocal,&portlocal,&netif) == -1)
    logmsg(WHO,111,FATAL,"unable to get local address");

  if (ip6_isv4mapped(iplocal)) {
    env("PROTO","TCP6");
    ipstr[ip4_fmt(ipstr,iplocal + 12)] = 0;
  } else {
    env("PROTO","TCP6");
    if (flagtcpenv && netif) env("TCP6INTERFACE",socket_getifname(netif));
    ipstr[ip6_fmt(ipstr,iplocal)] = 0;
  }

  env("SSLLOCALIP",ipstr);
  if (flagtcpenv) env("TCPLOCALIP",ipstr);

  strnum[fmt_ulong(strnum,portlocal)] = 0;
  env("SSLLOCALPORT",strnum);
  if (flagtcpenv) env("TCPLOCALPORT",strnum);

  x = forcelocal;
  if (!x)
    if (dns_name(&tmp,iplocal) >= 0) {
      if (!stralloc_0(&tmp)) nomem();
      x = tmp.s;
    }
  env("SSLLOCALHOST",x);
  if (flagtcpenv) env("TCPLOCALHOST",x);

  /* Remote */

  if (socket_remote(s,ipremote,&portremote,&netif) == -1)
    logmsg(WHO,111,FATAL,"unable to get remote address");

  if (ip6_isv4mapped(ipremote)) 
    ipstr[ip4_fmt(ipstr,ipremote + 12)] = 0;
  else
    ipstr[ip6_fmt(ipstr,ipremote)] = 0;

  env("SSLREMOTEIP",ipstr);
  if (flagtcpenv) env("TCPREMOTEIP",ipstr);

  strnum[fmt_ulong(strnum,portremote)] = 0;
  env("SSLREMOTEPORT",strnum);
  if (flagtcpenv) env("TCPREMOTEPORT",strnum);

  x = 0;
  if (flagremotehost)
    if (dns_name(&tmp,ipremote) >= 0) {
      if (!stralloc_0(&tmp)) nomem();
      x = tmp.s;
    }

  env("SSLREMOTEHOST",x);
  if (flagtcpenv) env("TCPREMOTEHOST",x);

  x = 0;
  if (flagremoteinfo)
    if (remoteinfo(&tmp,ipremote,portremote,iplocal,portlocal,itimeout,netif) == 0) {
      if (!stralloc_0(&tmp)) nomem();
      x = tmp.s;
    }
  env("SSLREMOTEINFO",x);
  if (flagtcpenv) env("TCPREMOTEINFO",x);

  /* Context */

  ctx = ssl_client();
  ssl_errstr();
  if (!ctx)
    logmsg(WHO,111,FATAL,"unable to create TLS context");

  switch (ssl_certkey(ctx,certfile,keyfile,passwd_cb)) {
    case -1: logmsg(WHO,111,ERROR,"unable to load certificate");
    case -2: logmsg(WHO,111,ERROR,"unable to load key pair");
    case -3: logmsg(WHO,111,ERROR,"key does not match certificate");
    default: break;
  }
  
  if (flagservercert && !ssl_ca(ctx,cafile,cadir,verifydepth))
    logmsg(WHO,111,ERROR,"unable to load CA list");

  if (!ssl_ciphers(ctx,ciphers))
    logmsg(WHO,111,ERROR,"unable to set cipher list");

  ssl = ssl_new(ctx,s);
  if (!ssl) logmsg(WHO,111,FATAL,"unable to create TLS instance");

  if (flagsni)
    if (!SSL_set_tlsext_host_name(ssl,hostname))
      logmsg(WHO,111,FATAL,B("unable to set TLS SNI extensions for hostname: ",(char *)hostname));

  for (cloop = 0; cloop < 2; ++cloop) {
    if (!ssl_timeoutconn(ssl,ctimeout[cloop])) goto SSLCONNECTED;
    if (!cloop && ctimeout[1]) continue;
    logmsg(WHO,111,FATAL,"unable to TLS connect");
  }

  _exit(111);

  SSLCONNECTED:

  ndelay_off(s);

  if (flagservercert)
    switch(ssl_verify(ssl,hostname,&certname)) {
      case -1:
        logmsg(WHO,110,ERROR,"no server certificate");
      case -2:
        logmsg(WHO,110,ERROR,"missing credentials (CA) or unable to validate server certificate");
      case -3:
        if (!stralloc_0(&certname)) nomem();
        if (flagname) 
          logmsg(WHO,110,ERROR,B("server hostname does not match certificate: ",(char *)hostname," <=> ",certname.s));
      default: break;
    }

  if (verbosity >= 2)
    log_who(WHO,B("tls connected to: ",ipstr," port: ",strnum));

  if (!flagdelay)
    socket_tcpnodelay(s); /* if it fails, bummer */

  if (pipe(pi) == -1) logmsg(WHO,111,FATAL,"unable to create pipe");
  if (pipe(po) == -1) logmsg(WHO,111,FATAL,"unable to create pipe");
  if (pi[0] == 7) {
    if (pipe(pt) == -1) logmsg(WHO,111,FATAL,"unable to create pipe");
    close(pi[0]); close(pi[1]);
    pi[0] = pt[0]; pi[1] = pt[1];
  }
  if (po[1] == 6) {
    if (pipe(pt) == -1) logmsg(WHO,111,FATAL,"unable to create pipe");
    close(po[0]); close(po[1]);
    po[0] = pt[0]; po[1] = pt[1];
  }

  switch (opt = fork()) {
    case -1:
      logmsg(WHO,111,FATAL,"unable to fork");
    case 0:
      break;
    default:
      close(pi[0]); close(po[1]);
      if (ssl_io(ssl,pi[1],po[0],progtimeout)) {
        logmsg(WHO,110,DROP,"unable to speak TLS");
        ssl_close(ssl);
        wait_pid(&wstat,opt);
        _exit(111);
      }
      ssl_close(ssl);
      if (wait_pid(&wstat,opt) > 0)
        _exit(wait_exitcode(wstat));
      _exit(0);
  }
  ssl_close(ssl); close(pi[1]); close(po[0]);

  if (flagsslenv && !ssl_client_env(ssl,0)) nomem();

  if (fd_move(6,pi[0]) == -1)
    logmsg(WHO,111,FATAL,"unable to set up descriptor 6");
  if (fd_move(7,po[1]) == -1)
    logmsg(WHO,111,FATAL,"unable to set up descriptor 7");
  sig_uncatch(sig_pipe);

  pathexec(argv);
  logmsg(WHO,111,FATAL,B("unable to run: ",*argv));

  return 0; /* never happens, but avoids compile warning */
}
