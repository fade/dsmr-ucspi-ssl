/** 
  @file  sslhandle.c
  @author web, feh
  @brief IPv6 enabled TLS framework for a preforking server
*/
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netdb.h>
#include <signal.h>
#include <arpa/inet.h>
#include "ucspissl.h"
#include "uint_t.h"
#include "str.h"
#include "byte.h"
#include "fmt.h"
#include "scan.h"
#include "ip.h"
#include "fd.h"
#include "exit.h"
#include "env.h"
#include "prot.h"
#include "open.h"
#include "wait.h"
#include "stralloc.h"
#include "alloc.h"
#include "buffer.h"
#include "getln.h"
#include "logmsg.h"
#include "getoptb.h"
#include "socket_if.h"
#include "ndelay.h"
#include "remoteinfo.h"
#include "rules.h"
#include "sig.h"
#include "iopause.h"
#include "dnsresolv.h"
#include "auto_cafile.h"
#include "auto_cadir.h"
#include "auto_ccafile.h"
#include "auto_dhfile.h"
#include "auto_certchainfile.h"
#include "auto_certfile.h"
#include "auto_keyfile.h"
#include "auto_ciphers.h"
#include "iopause.h"
#include "coe.h"
#include "lock.h"


extern void server(int argc,char * const argv[]);
char *who; 

int verbosity = 1;
int flagkillopts = 1;
int flagafter = 0;
int flagdelay = 0;
const char *banner = "";
int flagremoteinfo = 1;
int flagremotehost = 1;
int flagparanoid = 0;
int flagclientcert = 0;
int flagsslenv = 0;
int flagtcpenv = 0;
unsigned long timeout = 26;
unsigned long ssltimeout = 26;
unsigned int progtimeout = 3600;
uint32 netif = 0;
int selfpipe[2];
int flagexit = 0;
int flagdualstack = 0;

static stralloc tcpremoteinfo = {0};

uint16 localport;
char localportstr[FMT_ULONG];
char localip[16] = { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 };
char localipstr[IP6_FMT];
static stralloc localhostsa;
const char *localhost = 0;
const char *lockfile = 0;
int fdlock;

uint16 remoteport;
char remoteportstr[FMT_ULONG];
char remoteip[16];
char remoteipstr[IP6_FMT];
static stralloc remotehostsa;
char *remotehost = 0;

const char *hostname;
const char *loopback = "127.0.0.1";

static char strnum[FMT_ULONG];
static char strnum2[FMT_ULONG];

static stralloc tmp;
static stralloc fqdn;
static stralloc addresses;
static stralloc certname;
stralloc envplus = {0};
stralloc envtmp = {0};

char bspace[16];
buffer b;

SSL_CTX *ctx;
const char *certchainfile = auto_certchainfile;
const char *certfile = auto_certfile;
const char *keyfile = auto_keyfile;
stralloc password = {0};
int match = 0;
const char *cafile = auto_cafile;
const char *ccafile = auto_ccafile;
const char *cadir = auto_cadir;
const char *ciphers = auto_ciphers;
int verifydepth = 1;
const char *dhfile = auto_dhfile;
int rsalen = SSL_RSA_LEN;

int pi[2];
int po[2];

X509 *cert;
char buf[SSL_NAME_LEN];

char **e;
char **e1;

/* ---------------------------- child */


int flagdeny = 0;
int flagallow = 0;
int flagallownorules = 0;
const char *fnrules = 0;
const char *fniprules = 0;

void drop_nomem(void) 
{
  logmsg(who,111,FATAL,"out of memory");
}
void drop_notemp(void) 
{
  logmsg(who,111,FATAL,"out of timestamps");
}
void cats(const char *s) 
{
  if (!stralloc_cats(&tmp,s)) drop_nomem();
}
void append(const char *ch) 
{
  if (!stralloc_append(&tmp,ch)) drop_nomem();
}
void safecats(const char *s) 
{
  char ch;
  int i;

  for (i = 0;i < 100;++i) {
    ch = s[i];
    if (!ch) return;
    if (ch < 33) ch = '?';
    if (ch > 126) ch = '?';
    if (ch == '%') ch = '?'; /* logger stupidity */
    append(&ch);
  }
  cats("...");
}
void env(const char *s,const char *t) 
{
  if (!s) return;
  if (!stralloc_copys(&envtmp,s)) drop_nomem();
  if (t) {
    if (!stralloc_cats(&envtmp,"=")) drop_nomem();
    if (!stralloc_cats(&envtmp,t)) drop_nomem();
  }
  if (!stralloc_0(&envtmp)) drop_nomem();
  if (!stralloc_cat(&envplus,&envtmp)) drop_nomem();
}
static void env_def() {
  unsigned int elen;
  unsigned int i;
  unsigned int j;
  unsigned int split;
  unsigned int t;

  if (!stralloc_cats(&envplus,"")) return;

  elen = 0;
  for (i = 0; environ[i]; ++i)
    ++elen;
  for (i = 0; i < envplus.len; ++i)
    if (!envplus.s[i])
      ++elen;

  e = (char **) alloc((elen + 1) * sizeof(char *));
  if (!e) return;

  elen = 0;
  for (i = 0; environ[i]; ++i)
    e[elen++] = environ[i];

  j = 0;
  for (i = 0; i < envplus.len; ++i)
    if (!envplus.s[i]) {
      split = str_chr(envplus.s + j,'=');
      for (t = 0;t < elen;++t)
	      if (byte_equal(envplus.s + j,split,e[t]))
	    if (e[t][split] == '=') {
	      --elen;
	      e[t] = e[elen];
	      break;
	    }
      if (envplus.s[j + split])
        e[elen++] = envplus.s + j;
      j = i + 1;
  }
  e[elen] = 0;

  e1 = environ;
  environ = e;
}
void env_reset(void) 
{
  if (e) {
    if (e != environ) {
      alloc_free((char *)e);
      logmsg(who,111,FATAL,"environ changed");
    }
  }

  environ = e1;
  envplus.len = 0;
}
int error_warn(const char *x) 
{
  if (!x) return 0;
  log_who(who,"x");
  return 0;
}
void drop_rules(const char *fnbase) 
{
  logmsg(who,111,FATAL,B("unable to read: ",fnbase));
}

void found(char *data,unsigned int datalen) 
{
  unsigned int next0;
  unsigned int split;

 flagallow = 1; // used for IP match only

  while ((next0 = byte_chr(data,datalen,0)) < datalen) {
    switch(data[0]) {
      case 'D':
	      flagdeny = 1; flagallow = 0;
	      break;
      case '+':
        flagallow = 2; // qualified match
	      split = str_chr(data + 1,'=');
	      if (data[1 + split] == '=') {
	        data[1 + split] = 0;
	        env(data + 1,data + 1 + split + 1);
	      }
	      break;
    }
    ++next0;
    data += next0; datalen -= next0;
  }
}

int doit(int t) 
{
  int j;
  SSL *ssl;
  uint32 netif;

  if (ip6_isv4mapped(remoteip)) {
    remoteipstr[ip4_fmt(remoteipstr,remoteip + 12)] = 0;
    localipstr[ip4_fmt(localipstr,localip + 12)] = 0;
  } else {
    remoteipstr[ip6_fmt(remoteipstr,remoteip)] = 0;
    localipstr[ip6_fmt(localipstr,localip)] = 0;
  }

  if (verbosity >= 2) {
    strnum[fmt_ulong(strnum,getpid())] = 0;
    log_who(who,B("pid ",strnum," from ",remoteipstr));
  }

  if (socket_local(t,localip,&localport,&netif) == -1)
    logmsg(who,111,FATAL,"unable to get local address");

  remoteportstr[fmt_ulong(remoteportstr,remoteport)] = 0;

  if (!localhost)
    if (dns_name(&localhostsa,localip) >= 0)
      if (localhostsa.len) {
        if (!stralloc_0(&localhostsa)) drop_nomem();
        localhost = localhostsa.s;
      }

/* Early evaluation of IP rules (only) */

  if (fniprules) {
    int fdrules;
    fdrules = open_read(fniprules);
    if (fdrules == -1) {
      if (errno != ENOENT) drop_rules(fniprules);
      if (!flagallownorules) drop_rules(fniprules);
    } else {
      if (rules(found,fdrules,remoteipstr,0,0) == -1) 
        drop_rules(fniprules);
      close(fdrules);
    }
  }

  if (flagdeny) goto FINISH;
  if (flagallow) fnrules = 0;  // you need to know what you are doing

  if (flagremotehost)
    if (dns_name(&remotehostsa,remoteip) >= 0)
      if (remotehostsa.len) {
        if (flagparanoid) {
          if (dns_ip6(&tmp,&remotehostsa) >= 0)
            for (j = 0; j + 16 <= tmp.len; j += 16)
              if (byte_equal(remoteip,16,tmp.s + j)) {
                flagparanoid = 0;
                break;
              }
          if (dns_ip4(&tmp,&remotehostsa) >= 0)
            for (j = 0; j + 4 <= tmp.len; j += 4)
              if (byte_equal(remoteip,4,tmp.s + j)) {
                flagparanoid = 0;
                break;
              }
        }
        if (!flagparanoid) {
          if (!stralloc_0(&remotehostsa)) drop_nomem();
          remotehost = remotehostsa.s;
        } 
      }

  if (flagremoteinfo) {
    if (remoteinfo(&tcpremoteinfo,remoteip,remoteport,localip,localport,timeout,netif) == -1)
      flagremoteinfo = 0;
    if (!stralloc_0(&tcpremoteinfo)) drop_nomem();
  }

  if (fnrules) {
    int fdrules;
    flagdeny = 0;
    fdrules = open_read(fnrules);
    if (fdrules == -1) {
      if (errno != ENOENT) drop_rules(fnrules);
      if (!flagallownorules) drop_rules(fnrules);
    } else {
      if (rules(found,fdrules,remoteipstr,remotehost,flagremoteinfo ? tcpremoteinfo.s : 0) == -1)
        drop_rules(fnrules);
      close(fdrules);
    }
  }

  /* Set environment variables */

  env("PROTO","TLS");
  env("SSLLOCALIP",localipstr);
  env("SSLLOCALPORT",localportstr);
  env("SSLLOCALHOST",localhost);
  env("SSLREMOTEIP",remoteipstr);
  env("SSLREMOTEPORT",remoteportstr);
  env("SSLREMOTEHOST",remotehost);
  env("SSLREMOTEINFO",flagremoteinfo ? tcpremoteinfo.s : 0);

  if (flagtcpenv) {
    env("TCPLOCALIP",localipstr);
    env("TCPLOCALPORT",localportstr);
    env("TCPLOCALHOST",localhost);
    env("TCPREMOTEIP",remoteipstr);
    env("TCPREMOTEPORT",remoteportstr);
    env("TCPREMOTEHOST",remotehost);
    env("TCPREMOTEINFO",flagremoteinfo ? tcpremoteinfo.s : 0);
    if (!ip6_isv4mapped(localip)) {
      env("PROTO","TCP6");
      env("TCP6LOCALIP",localipstr);
      env("TCP6LOCALHOST",localhost);
      env("TCP6LOCALPORT",localportstr);
      env("TCP6REMOTEIP",remoteipstr);
      env("TCP6REMOTEPORT",remoteportstr);
      env("TCP6REMOTEHOST",remotehost);
      if (netif)
        env("TCP6INTERFACE",socket_getifname(netif));
    } else
      env("PROTO","TCP");
  }

  FINISH:

  if (verbosity >= 2) {
    strnum[fmt_ulong(strnum,getpid())] = 0;
    if (!stralloc_copys(&tmp,who)) drop_nomem();
    if (!stralloc_cats(&tmp,": ")) drop_nomem();
    safecats(flagdeny ? "deny" : "ok");
    cats(" "); safecats(strnum);
    cats(" "); if (localhost) safecats(localhost);
    cats(":"); safecats(localipstr);
    cats(":"); safecats(localportstr);
    cats(" "); if (remotehost) safecats(remotehost);
    cats(":"); safecats(remoteipstr);
    cats(":"); if (flagremoteinfo) safecats(tcpremoteinfo.s);
    cats(":"); safecats(remoteportstr);
    cats("\n");
    buffer_putflush(buffer_2,tmp.s,tmp.len);
  }

  if (flagdeny) {
    close(t);
    return(0);
  }

  if (pipe(pi) == -1) logmsg(who,111,FATAL,"unable to create pipe");
  if (pipe(po) == -1) logmsg(who,111,FATAL,"unable to create pipe");

  ssl = ssl_new(ctx,t);
  if (!ssl) logmsg(who,111,FATAL,"unable to create SSL instance");
  if (ndelay_on(t) == -1)
    logmsg(who,111,FATAL,"unable to set socket options");
  if (ssl_timeoutaccept(ssl,ssltimeout) == -1) {
    strnum[fmt_ulong(strnum,getpid())] = 0;
    logmsg(who,110,DROP,B("unable to TLS accept for pid:",strnum));
    ssl_error(error_warn);
  }

  if (verbosity >= 2) {
    strnum[fmt_ulong(strnum,getpid())] = 0;
    log_who(who,B("tls ",strnum," accept "));
  }

  if (flagclientcert) {
    switch(ssl_verify(ssl,remotehost,&certname)) {
      case -1:
        logmsg(who,110,ERROR,"no client certificate");
      case -2:
        logmsg(who,110,ERROR,"missing credentials (CA) or unable to validate client certificate");
      case -3:
        if (!stralloc_0(&certname)) drop_nomem();
        logmsg(who,110,ERROR,B("client hostname name does not match certificate: ",remotehost," <=> ",certname.s));
      default: 
        break;
    }
  }

  switch(fork()) {
    case -1:
      logmsg(who,111,FATAL,"unable to fork ");
    case 0:
      close(pi[0]); close(po[1]);
      sig_uncatch(sig_child);
      sig_unblock(sig_child);
      if (ssl_io(ssl,pi[1],po[0],progtimeout) == -1) {
        strnum[fmt_ulong(strnum,getpid())] = 0;
        logmsg(who,-99,WARN,B("unable to speak TLS for pid: ",strnum));
        ssl_error(error_warn);
        _exit(111);
      }
      _exit(0);
  }
  close(pi[1]); close(po[0]);

  if (flagsslenv && !ssl_server_env(ssl,&envplus)) drop_nomem();
  env_def();

  if (fd_move(0,pi[0]) == -1)
    logmsg(who,111,FATAL,"unable to set up descriptor 0");
  if (fd_move(1,po[1]) == -1)
    logmsg(who,111,FATAL,"unable to set up descriptor 1");

  if (flagkillopts) {
    socket_ipoptionskill(t);
  }
  if (!flagdelay)
    socket_tcpnodelay(t);

  if (*banner) {
    buffer_init(&b,buffer_unixwrite,1,bspace,sizeof(bspace));
    if (buffer_putsflush(&b,banner) == -1)
      logmsg(who,111,FATAL,"unable to print banner");
  }

  ssl_free(ssl);
  return 1;
}

void done(void) 
{
  if (verbosity >= 2) {
    strnum[fmt_ulong(strnum,getpid())] = 0;
    if (!stralloc_copys(&tmp,who)) drop_nomem();
    if (!stralloc_cats(&tmp,": ")) drop_nomem();
    cats("done "); safecats(strnum); cats("\n");
    buffer_putflush(buffer_2,tmp.s,tmp.len);
  }
}


/* ---------------------------- parent */

void usage(void)
{
  logmsg(who,100,USAGE,B(who,"\
[ -1346UXpPhHrRoOdDqQviIeEsS ] \
[ -c limit ] \
[ -x rules.cdb ] \
[ -B banner ] \
[ -g gid ] \
[ -u uid ] \
[ -b backlog ] \
[ -l localname ] \
[ -t timeout ] \
[ -T ssltimeout ] \
[ -w progtimeout ] \
[ -f lockfile ] \
[ -I interface ] \
host port program"));
}

unsigned long limit = 40;
unsigned long numchildren = 0;

int flag1 = 0;
int flag3 = 0;
unsigned long backlog = 20;
unsigned long uid = 0;
unsigned long gid = 0;

void printstatus(void) 
{
  if (verbosity < 2) return;
  strnum[fmt_ulong(strnum,numchildren)] = 0;
  strnum2[fmt_ulong(strnum2,limit)] = 0;
  log_who(who,B("status: ",strnum,"/",strnum2));
}

void trigger(void) 
{
  buffer_unixwrite(selfpipe[1],"",1);
}

void sigterm(int dummy) 
{
  int pid;

  flagexit = 1;
  pid = getpid();
  if (pid < 0) logmsg(who,111,FATAL,"cannot get pid");
  kill(-pid,SIGTERM);
  trigger();
}

void sigchld(int dummy) 
{
  int wstat;
  int pid;
 
  while ((pid = wait_nohang(&wstat)) > 0) {
    if (verbosity >= 2) {
      strnum[fmt_ulong(strnum,pid)] = 0;
      strnum2[fmt_ulong(strnum2,wstat)] = 0;
      log_who(who,B("end ",strnum," status ",strnum2));
    }
    if (numchildren) --numchildren; printstatus();
    if (flagexit && !numchildren) _exit(0);
  }
  trigger();
}

void read_passwd(void) 
{
  if (!password.len) {
    buffer_init(&b,buffer_unixread,3,bspace,sizeof(bspace));
    if (getln(&b,&password,&match,'\0') == -1)
      logmsg(who,111,ERROR,"unable to read password");
    close(3);
    if (match) --password.len;
  }
}

int passwd_cb(char *buff,int size,int rwflag,void *userdata) 
{
  if (size < password.len)
    logmsg(who,111,ERROR,"password too long");

  byte_copy(buff,password.len,password.s);
  return password.len;
}

void spawn(int s,int argc,char * const *argv) 
{
  int t;

  while (numchildren >= limit) sig_pause();
  while (numchildren < limit) {
    ++numchildren; printstatus();
 
    switch(fork()) {
      case 0:
        sig_uncatch(sig_child);
        sig_unblock(sig_child);
        sig_uncatch(sig_term);
        sig_uncatch(sig_pipe);
        for (;;) {
          if (lockfile) {
            if (lock_ex(fdlock) == -1)
              logmsg(who,111,FATAL,B("unable to lock: ",(char *)lockfile));
            if (flagdualstack)
              t = socket_accept6(s,remoteip,&remoteport,&netif);
            else 
              t = socket_accept4(s,remoteip,&remoteport);
            lock_un(fdlock);
          } else {
            if (flagdualstack)
              t = socket_accept6(s,remoteip,&remoteport,&netif);
            else 
              t = socket_accept4(s,remoteip,&remoteport);
          }

          if (t == -1) continue;
          if (!doit(t)) continue;
          server(argc,argv);
          close(0); close(1);
          env_reset();
          done();
        }
        break;
     case -1:
        logmsg(who,111,FATAL,"unable to fork");
        --numchildren; printstatus();
    }
  }
}

int main(int argc,char * const argv[]) 
{
  int opt;
  struct servent *se;
  char *x;
  int j;
  int s;
  int ipflag = 0;
  iopause_fd io[2];
  char ch;
  struct taia deadline;
  struct taia stamp;
  unsigned long u;
 
  who = argv[0];
  while ((opt = getoptb(argc,(char **)argv,"dDvqQhHrRUXx:y:t:T:u:g:l:b:B:c:pPoO1346I:EeSsaAf:w:zZ")) != opteof)
    switch(opt) {
      case 'b': scan_ulong(optarg,&backlog); break;
      case 'c': scan_ulong(optarg,&limit); break;
      case 'X': flagallownorules = 1; break;
      case 'x': fnrules = optarg; break;
      case 'y': fniprules = optarg; break;
      case 'B': banner = optarg; break;
      case 'd': flagdelay = 1; break;
      case 'D': flagdelay = 0; break;
      case 'v': verbosity = 2; break;
      case 'q': verbosity = 0; break;
      case 'Q': verbosity = 1; break;
      case 'P': flagparanoid = 0; break;
      case 'p': flagparanoid = 1; break;
      case 'O': flagkillopts = 1; break;
      case 'o': flagkillopts = 0; break;
      case 'H': flagremotehost = 0; break;
      case 'h': flagremotehost = 1; break;
      case 'R': flagremoteinfo = 0; break;
      case 'r': flagremoteinfo = 1; break;
      case 't': scan_ulong(optarg,&timeout); break;
      case 'T': scan_ulong(optarg,&ssltimeout); break;
      case 'U': x = env_get("UID"); if (x) scan_ulong(x,&uid);
                x = env_get("GID"); if (x) scan_ulong(x,&gid); break;
      case 'u': scan_ulong(optarg,&uid); break;
      case 'g': scan_ulong(optarg,&gid); break;
      case 'l': localhost = optarg; break;
      case 'I': netif = socket_getifidx(optarg); break;
      case '1': flag1 = 1; break;
      case '3': flag3 = 1; break;
      case '4': ipflag = 1; break;
      case '6': ipflag = 2; break;
      case 'Z': flagclientcert = 0; break;
      case 'z': flagclientcert = 1; break;
      case 'S': flagsslenv = 0; break;
      case 's': flagsslenv = 1; break;
      case 'E': flagtcpenv = 0; break;
      case 'e': flagtcpenv = 1; break;
      case 'A': flagafter = 0; break;
      case 'a': flagafter = 1; break;
      case 'f': lockfile = optarg; break;
      case 'w': scan_uint(optarg,&progtimeout); break;
      default: usage();
    }
  argc -= optind;
  argv += optind;

  if (!verbosity) buffer_2->fd = -1;

  hostname = *argv++;
  if (!hostname || str_equal((char *)hostname,"")) usage();
  if (str_equal((char *)hostname,"0")) hostname = loopback;
  else if (str_equal((char *)hostname,":0")) {
    flagdualstack = 1;
    hostname = "::";
  }

  x = *argv++; --argc;
  if (!x) usage();
  if (!x[scan_ulong(x,&u)])
    localport = u;
  else {
    se = getservbyname(x,"tcp");
    if (!se)
      logmsg(who,111,FATAL,B("unable to figure out port number for: ",x));
    uint16_unpack_big((char*)&se->s_port,&localport);
  }

  if ((x = env_get("VERIFYDEPTH"))) {
    scan_ulong(x,&u);
    verifydepth = u;
  }

  if ((x = env_get("CAFILE"))) cafile = x;
  if (cafile && str_equal((char *)cafile,"")) cafile = 0;

  if ((x = env_get("CCAFILE"))) ccafile = x;
  if (ccafile && str_equal((char *)ccafile,"")) ccafile = 0;
  if (!flagclientcert) ccafile = 0;

  if ((x = env_get("CADIR"))) cadir = x;
  if (cadir && str_equal((char *)cadir,"")) cadir= 0;

  if ((x = env_get("CERTCHAINFILE"))) certchainfile = x;
  if (certchainfile && str_equal((char *)certchainfile,"")) certchainfile = 0;

  if ((x = env_get("CERTFILE"))) certfile = x;
  if (certfile && str_equal((char *)certfile,"")) certfile = 0;

  if ((x = env_get("KEYFILE"))) keyfile = x;
  if (keyfile && str_equal((char *)keyfile,"")) keyfile = 0;

  if ((x = env_get("DHFILE"))) dhfile = x;
  if (dhfile && str_equal((char *)dhfile,"")) dhfile = 0;

  if ((x = env_get("CIPHERS"))) ciphers = x;
  if (ciphers && str_equal((char *)ciphers,"")) ciphers = 0;

  if (setsid() == -1)
    if (getpgrp() != getpid())
      logmsg(who,111,FATAL,"unable to create process group");
    
  if (lockfile) {
    fdlock = open_append(lockfile);
    if (fdlock == -1)
      logmsg(who,111,FATAL,B("unable to open: ",(char *)lockfile));
  }

  if (pipe(selfpipe) == -1)
    logmsg(who,111,FATAL,"unable to create pipe");

  coe(selfpipe[0]);
  coe(selfpipe[1]);
  ndelay_on(selfpipe[0]);
  ndelay_on(selfpipe[1]);

  sig_block(sig_child);
  sig_catch(sig_child,sigchld);
  sig_catch(sig_term,sigterm);
  sig_ignore(sig_pipe);
 
  /* IP address only */

  if (ip4_scan(hostname,localip)) {
    if (!stralloc_copyb(&addresses,(char *)V4mappedprefix,12)) drop_nomem();
    if (!stralloc_catb(&addresses,localip,4)) drop_nomem();
    byte_copy(localip,16,addresses.s);
  } else if (ip6_scan(hostname,localip)) {
      if (!stralloc_copyb(&addresses,localip,16)) drop_nomem();
      byte_copy(localip,16,addresses.s);
  }

  /* Asynchronous DNS IPv4/IPv6 Name qualification */

  if (!addresses.len) {
    if (!stralloc_copys(&tmp,hostname)) drop_nomem();
    if (dns_ip_qualify(&addresses,&fqdn,&tmp) < 0)
      logmsg(who,111,FATAL,B("temporarily unable to figure out IP address for: ",(char *)hostname));

    byte_copy(localip,16,addresses.s);

    for (j = 0; j < addresses.len; j += 16) {  // Select best matching IP address
      if (ipflag == 1 && !ip6_isv4mapped(addresses.s + j)) continue;
      if (ipflag == 2 && !ip6_isv4mapped(addresses.s + j)) continue;
      byte_copy(localip,16,addresses.s + j);
    }

  }
  if (addresses.len < 16)
    logmsg(who,111,FATAL,B("no IP address for: ",(char *)hostname));

  if (ip6_isv4mapped(localip))
    s = socket_tcp4();
  else
    s = socket_tcp6();
  if (s == -1)
    logmsg(who,111,FATAL,"unable to create socket");

  if (flagdualstack)
    socket_dualstack(s);
  if (socket_bind_reuse(s,localip,localport,netif) == -1)
    logmsg(who,111,FATAL,"unable to bind");
  if (socket_local(s,localip,&localport,&netif) == -1)
    logmsg(who,111,FATAL,"unable to get local address");
  if (socket_listen(s,backlog) == -1)
    logmsg(who,111,FATAL,"unable to listen");
  ndelay_off(s);

  if (!flagafter) {
    if (gid) if (prot_gid(gid) == -1)
      logmsg(who,111,FATAL,"unable to set gid");
    if (uid) if (prot_uid(uid) == -1)
      logmsg(who,111,FATAL,"unable to set uid");
  }

  if (ip6_isv4mapped(localip))
    localipstr[ip4_fmt(localipstr,localip + 12)] = 0;
  else
    localipstr[ip6_fmt(localipstr,localip)] = 0;

  localportstr[fmt_ulong(localportstr,localport)] = 0;

  if (flag1) {
    buffer_init(&b,buffer_unixwrite,1,bspace,sizeof(bspace));
    buffer_puts(&b,localipstr);
    buffer_puts(&b," : ");
    buffer_puts(&b,localportstr);
    buffer_puts(&b,"\n");
    buffer_flush(&b);
  }
 
  if (flag3) read_passwd();

  ctx = ssl_server();
  ssl_errstr();
  if (!ctx) logmsg(who,111,FATAL,"unable to create TLS context");

  if (certchainfile) {
    switch (ssl_chainfile(ctx,certchainfile,keyfile,passwd_cb)) {
      case -1: logmsg(who,111,ERROR,"unable to load certificate chain file");
      case -2: logmsg(who,111,ERROR,"unable to load key");
      case -3: logmsg(who,111,ERROR,"key does not match certificate");
      default: break;
    }
  } else {
    switch (ssl_certkey(ctx,certfile,keyfile,passwd_cb)) {
      case -1: logmsg(who,111,ERROR,"unable to load certificate");
      case -2: logmsg(who,111,ERROR,"unable to load key");
      case -3: logmsg(who,111,ERROR,"key does not match certificate");
      default: break;
    }
  }

  if (flagclientcert) {
    if (!ssl_ca(ctx,cafile,cadir,verifydepth))
      logmsg(who,111,ERROR,"unable to load CA list");
    if (!ssl_cca(ctx,ccafile))
      logmsg(who,111,ERROR,"unable to load client CA list");
  }
  if (!ssl_params_rsa(ctx,rsalen))
    logmsg(who,111,ERROR,"unable to set RSA parameters");
  if (!ssl_params_dh(ctx,dhfile))
    logmsg(who,111,ERROR,"unable to set DH parameters");

  if (flagafter) {
    if (gid) if (prot_gid(gid) == -1)
      logmsg(who,111,FATAL,"unable to set gid");
    if (uid) if (prot_uid(uid) == -1)
      logmsg(who,111,FATAL,"unable to set uid");
  }

  if (!ssl_ciphers(ctx,ciphers))
    logmsg(who,111,ERROR,"unable to set cipher list");

  if (verbosity >= 2) {
    strnum[fmt_ulong(strnum,getpid())] = 0;
    strnum2[fmt_ulong(strnum2,rsalen)] = 0;
    log_who(who,B("ciphers ",strnum," ",(char *)ciphers));
    log_who(who,B("cafile ",strnum," ",(char *)cafile));
    log_who(who,B("ccafile ",strnum," ",(char *)ccafile));
    log_who(who,B("cadir ",strnum," ",(char *)cadir));
    log_who(who,B("certchainfile ",strnum," ",(char *)certchainfile));
    log_who(who,B("cert ",strnum," ",(char *)certfile));
    log_who(who,B("key ",strnum," ",(char *)keyfile));
    /* XXX */
    log_who(who,B("dhparam ",strnum," ",(char *)dhfile," ",strnum2));
  }

  close(0);
  close(1);
  printstatus();

  for (;;) {
    int pause_ret, read_ret;
    if (!flagexit) spawn(s,argc,argv);

    sig_unblock(sig_child);
    io[0].fd = selfpipe[0];
    io[0].events = IOPAUSE_READ;
    taia_now(&stamp);
    taia_uint(&deadline,3600);
    taia_add(&deadline,&stamp,&deadline);
    pause_ret = iopause(io,1,&deadline,&stamp);
    sig_block(sig_child);

    if (flagexit && !numchildren) _exit(0);
    while ((read_ret = buffer_unixread(selfpipe[0],&ch,1)) == 1)
      ;
    if ((pause_ret > 0) && (read_ret == 0)) {
      flagexit = 1;
      --numchildren;
    }
    if (flagexit && !numchildren) _exit(0);
  }
}
