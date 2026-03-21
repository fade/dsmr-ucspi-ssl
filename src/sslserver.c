/** 
  @file  sslserver.c
  @author web, fefe, feh
  @brief IPv6 enabled dualstack sslserver
*/
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <signal.h>
#include <netdb.h>
#include <fcntl.h>
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
#include "genalloc.h"
#include "alloc.h"
#include "buffer.h"
#include "getln.h"
#include "error.h"
#include "logmsg.h"
#include "getoptb.h"
#include "pathexec.h"
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
#include "auto_certfile.h"
#include "auto_certchainfile.h"
#include "auto_keyfile.h"
#include "auto_ciphers.h"

#define WHO "sslserver"

int verbosity = 1;
int flagkillopts = 1;
int flagdelay = 0;
const char *banner = "";
int flagremoteinfo = 0;
int flagremotehost = 1;
int flagparanoid = 0;
int flagclientcert = 0;
int flagsslenv = 0;
int flagtcpenv = 1;
int flagsslwait = 0;
unsigned long timeout = 26;
unsigned long ssltimeout = 26;
unsigned int progtimeout = 3600;
uint32 netif = 0;

static stralloc tcpremoteinfo;

uint16 localport;
char iplocal[16] = { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 };
char localportstr[FMT_ULONG];
char localip[16];
char localipstr[IP6_FMT];
static stralloc localhostsa;
const char *localhost = 0;

uint16 remoteport;
char remoteportstr[FMT_ULONG];
char remoteip[16];
char remoteipstr[IP6_FMT];
static stralloc remotehostsa;
char *remotehost = 0;
char *verifyhost = 0;

const char *hostname;
const char *thishost = "0.0.0.0";

unsigned long uid = 0;
unsigned long gid = 0;

static char strnum[FMT_ULONG];
static char strnum2[FMT_ULONG];
static char strnum3[FMT_ULONG];

static stralloc tmp;
static stralloc fqdn;
static stralloc addresses;

unsigned long limit = 40;
unsigned long numchildren = 0;
unsigned long ipchildren = 0;
unsigned long maxconip = 40;

char bspace[16];
buffer bo;

void drop_nomem(void)
{
  logmsg(WHO,111,FATAL,"out of memory");
}

/* ---------------------------- per ip limit */

struct child {
  char ipaddr[16];
  uint32 num;
};

GEN_ALLOC_typedef(child_alloc,struct child,c,len,a)
GEN_ALLOC_readyplus(child_alloc,struct child,c,len,a,i,n,x,24,child_readyplus)
GEN_ALLOC_append(child_alloc,struct child,c,len,a,i,n,x,24,child_readyplus,child_append)

child_alloc children = {0};

void ipchild_append(char ip[16],unsigned long n)
{
  struct child *ipchild = 0;
  int i;

  for (i = 0; i <= n; ++i) {
    ipchild = &children.c[i];
    if (byte_equal(ipchild->ipaddr,16,ip)) {
      ++ipchild->num;
      break;
    } else {
      byte_copy(ipchild->ipaddr,16,ip);
      ++ipchild->num;
      break;
    }
  }
}

void ipchild_clear(char ip[16])
{
  struct child *ipchild = 0;
  int i;

  for (i = 0; i <= children.len; ++i) {
    ipchild = &children.c[i];
    if (byte_equal(ipchild->ipaddr,16,ip)) {
      if (ipchild->num) --ipchild->num;
      break;
    }
  }
}

int ipchild_limit(char ip[16],unsigned long n)
{
  int i;

  for (i = 0; i <= n; ++i)
    if (byte_equal(children.c[i].ipaddr,16,ip))
      return children.c[i].num;

  return 0;
}

SSL_CTX *ctx;
const char *certchainfile = auto_certchainfile;
const char *certfile = auto_certfile;
const char *keyfile = auto_keyfile;
stralloc password = {0};
stralloc certfqdn = {0};
int match = 0;
const char *cafile = auto_cafile;
const char *ccafile = auto_ccafile;
const char *cadir = auto_cadir;
const char *ciphers = auto_ciphers;
int verifydepth = 1;
const char *dhfile = auto_dhfile;
int rsalen = SSL_RSA_LEN;

char * const *prog;

int pi[2];
int po[2];
int pt[2];

stralloc envsa = {0};

X509 *cert;
char buf[SSL_NAME_LEN];

/* ---------------------------- child */

int flagdualstack = 0;
int flagdeny = 0;
int flagallow = 0;
int flagallownorules = 0;
const char *fnrules = 0;
const char *fniprules = 0;

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
  if (!pathexec_env(s,t)) drop_nomem();
}

void drop_rules(const char *fnbase) 
{
  logmsg(WHO,110,FATAL,B("unable to read: ",fnbase));
}

void found(char *data,unsigned int datalen) 
{
  unsigned int next0;
  unsigned int split;

  flagallow = 1; // used for IP match only

  while ((next0 = byte_chr(data,datalen,0)) < datalen) {
    switch (data[0]) {
      case 'D':
        flagdeny = 1; flagallow = 0;
        break;
      case '+':
        flagallow = 2; // qualified match
        split = str_chr(data + 1,'=');
        if (data[1 + split] == '=') {
          data[1 + split] = 0;
          env(data + 1,data + 1 + split + 1);

          if (!str_diff(data + 1,"MAXCONIP")) {
            scan_ulong(data + 1 + split + 1,&maxconip);
            if (limit && maxconip > limit) maxconip = limit;
            if (ipchildren >= maxconip) flagdeny = 2;
          }

        }
        break;
    }
    ++next0;
    data += next0; datalen -= next0;
  }
}

void doit(int t) 
{
  int j;
  SSL *ssl = 0;
  int wstat;
  int sslctl[2];
  char *s;
  unsigned long tmp_long;
  char ssl_cmd;
  stralloc ssl_env = {0};
  int bytesleft;
  char envbuf[8192];
  int childpid;
  uint32 netif = 0;
  stralloc tlsinfo = {0};
  
  if (pipe(pi) == -1) logmsg(WHO,111,FATAL,"unable to create pipe");
  if (pipe(po) == -1) logmsg(WHO,111,FATAL,"unable to create pipe");
  if (socketpair(AF_UNIX,SOCK_STREAM,0,sslctl) == -1) 
    logmsg(WHO,111,FATAL,"unable to create socketpair");
 
/* Get remote IP and FQDN to validate X.509 cert */

  if (ip6_isv4mapped(remoteip)) {
    localipstr[ip4_fmt(localipstr,localip + 12)] = 0;
    remoteipstr[ip4_fmt(remoteipstr,remoteip + 12)] = 0;
  } else {
    remoteipstr[ip6_fmt(remoteipstr,remoteip)] = 0;
    localipstr[ip6_fmt(localipstr,localip)] = 0;
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
  if (flagallow) fnrules = 0;   // you need to know what you are doing

/* Early lookup of remote information (before child invoked) */

  if (flagremotehost)
    if (dns_name(&remotehostsa,remoteip) >= 0)
      if (remotehostsa.len) {
        if (flagparanoid) {
          verifyhost = remoteipstr;
          if (dns_ip6(&tmp,&remotehostsa) >= 0)
            for (j = 0; j + 16 <= tmp.len; j += 16)
              if (byte_equal(remoteip,16,tmp.s + j)) {
                flagparanoid = 0;
                break;
              }
          if (dns_ip4(&tmp,&remotehostsa) >= 0) 
            for (j = 0; j + 4 <= tmp.len; j += 4)
              if (byte_equal(remoteip + 12,4,tmp.s + j)) {
                flagparanoid = 0;
                break;
              }
          }
        if (!flagparanoid) {
          if (!stralloc_0(&remotehostsa)) drop_nomem();
            remotehost = remotehostsa.s;
            verifyhost = remotehostsa.s;
        }
      }

  if (flagremoteinfo) {
    if (remoteinfo(&tcpremoteinfo,remoteip,remoteport,localip,localport,timeout,netif) == -1)
      flagremoteinfo = 0;
    if (!stralloc_0(&tcpremoteinfo)) drop_nomem();
  }

  if (fnrules) {
    int fdrules;
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

  if (flagdeny) goto FINISH;

/* Prepare the child process */

  switch (childpid = fork()) {
    case -1:
      logmsg(WHO,111,FATAL,"unable to fork");
    case 0:
      /* Child */
      close(sslctl[0]);
      break;
    default:
      /* Parent */

      close(pi[0]); close(po[1]); close(sslctl[1]);

      if ((s = env_get("SSL_CHROOT")))
        if (chroot(s) == -1) {
          kill(childpid,SIGTERM);
          logmsg(WHO,111,FATAL,"unable to chroot");
        }
      
      if ((s = env_get("SSL_GID"))) {
        scan_ulong(s,&tmp_long);
        gid = tmp_long;
      }
      if (gid) if (prot_gid(gid) == -1) {
        kill(childpid,SIGTERM);
        logmsg(WHO,111,FATAL,"unable to set gid");
      }

      if ((s = env_get("SSL_UID"))) {
        scan_ulong(s,&tmp_long);
        uid = tmp_long;
      }
      if (uid)
        if (prot_uid(uid) == -1) {
          kill(childpid,SIGTERM);
          logmsg(WHO,111,FATAL,"unable to set uid");
        }

/* Get remote IP info to report in logmsg */

      if (ip6_isv4mapped(remoteip)) 
        remoteipstr[ip4_fmt(remoteipstr,remoteip + 12)] = 0;
      else
        remoteipstr[ip6_fmt(remoteipstr,remoteip)] = 0;

/* Read the TLS command socket. This will block until/unless TLS is requested. */

      if (read(sslctl[0],&ssl_cmd,1) == 1) {
        ssl = ssl_new(ctx,t);
        if (!ssl) {
          kill(childpid,SIGTERM);
          logmsg(WHO,111,FATAL,"unable to create TLS instance");
        }
        if (ndelay_on(t) == -1) {
          kill(childpid,SIGTERM);
          logmsg(WHO,111,FATAL,"unable to set socket options");
        }
        if (ssl_timeoutaccept(ssl,ssltimeout) == -1) {
          strnum[fmt_ulong(strnum,childpid)] = 0;
          kill(childpid,SIGTERM);
          logmsg(WHO,111,FATAL,B("unable to accept TLS from: ",remoteipstr," for pid: ",strnum," ",ERR_reason_error_string(ERR_peek_last_error())));
        }
      } else if (errno == EAGAIN) {
        strnum[fmt_ulong(strnum,childpid)] = 0;
        kill(childpid,SIGTERM);
        _exit(100);
      }

/* Check the remote client cert during TLS handshake; if requested */

      if (flagclientcert) {
        strnum[fmt_ulong(strnum,childpid)] = 0;
        if (flagclientcert == 2) verifyhost = 0;
          switch (ssl_verify(ssl,verifyhost,&certfqdn)) {
            case -1:
              kill(childpid,SIGTERM);
              logmsg(WHO,110,ERROR,B("no client certificate from: ",remoteipstr," for pid: ",strnum));
            case -2:
               kill(childpid,SIGTERM);
               logmsg(WHO,110,ERROR,B("missing credentials (CA) or unable to validate client certificate from: ",remoteipstr," for pid: ",strnum));
             case -3:
               kill(childpid,SIGTERM);
               if (!stralloc_0(&certfqdn)) drop_nomem();
               logmsg(WHO,110,ERROR,B("client hostname does not match certificate for pid: ",strnum," ",verifyhost," <=> ",certfqdn.s));
             default: 
               if (verbosity >= 2) {
                 strnum[fmt_ulong(strnum,childpid)] = 0;
                 logmsg(WHO,0,INFO,B("valid client cert received from: ",remoteipstr," for pid: ",strnum)); 
               }
               break;
          }
      }
 
/* Request TLS communication pipe from/to the child process (the application called) */
      
      if (ssl_cmd == 'Y') {
        ssl_server_env(ssl,&ssl_env);
        if (!stralloc_0(&ssl_env)) drop_nomem(); /* Add another NUL */
        env("SSLCTL",ssl_env.s); 

        for (bytesleft = ssl_env.len; bytesleft > 0; bytesleft -= j)
          if ((j = write(sslctl[0],ssl_env.s,bytesleft)) < 0) {
            kill(childpid,SIGTERM);
            logmsg(WHO,111,FATAL,"unable to write TLS environment");
          }
      }

      if (verbosity >= 2) {
        strnum[fmt_ulong(strnum,childpid)] = 0;
        if (verbosity >= 3 && ssl_env.len > 1) {
          s = ssl_env.s;
          if ((j = str_chr(s,'=')))
            if (!stralloc_copys(&tlsinfo,s + j + 1)) drop_nomem();
          if (!stralloc_cats(&tlsinfo,":")) drop_nomem();
          s = s + str_len(s) + 1;
          s = s + str_len(s) + 1;
          if ((j = str_chr(s,'=')))
            if (!stralloc_cats(&tlsinfo,s + j + 1)) drop_nomem();
          if (!stralloc_0(&tlsinfo)) drop_nomem();
          log_who(WHO,B("tls ",strnum," accept ",tlsinfo.s));
        } else
          log_who(WHO,B("tls ",strnum," accept"));
      }

      if (ssl_cmd == 'Y' || ssl_cmd == 'y') {
        if (ssl_io(ssl,pi[1],po[0],progtimeout) != 0) {
          strnum[fmt_ulong(strnum,childpid)] = 0;
          kill(childpid,SIGTERM);
          logmsg(WHO,111,ERROR,B("unable to speak TLS with: ",remoteipstr," for pid: ",strnum," ",ERR_reason_error_string(ERR_peek_last_error())));
        }
        if (wait_nohang(&wstat) > 0)
          _exit(wait_exitcode(wstat)); 
        ssl_close(ssl);
      }
      kill(childpid,SIGTERM);
      _exit(0);
  }

/* Child-only below this point */

  if (ip6_isv4mapped(remoteip)) 
    localipstr[ip4_fmt(localipstr,localip + 12)] = 0;
  else 
    localipstr[ip6_fmt(localipstr,localip)] = 0;
  localportstr[fmt_ulong(localportstr,localport)] = 0;

  if (socket_local(t,localip,&localport,&netif) == -1)
    logmsg(WHO,111,FATAL,B("unable to set local address/port: ",localipstr,"/",localportstr));

  if (verbosity >= 2) {
    strnum[fmt_ulong(strnum,getpid())] = 0;
    log_who(WHO,B("pid ",strnum," from ",remoteipstr));
  }

  if (!localhost)
    if (dns_name(&localhostsa,localip) >= 0)
      if (localhostsa.len) {
        if (!stralloc_0(&localhostsa)) drop_nomem();
        localhost = localhostsa.s;
      }

  remoteportstr[fmt_ulong(remoteportstr,remoteport)] = 0;

/* Setup environment variables */

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
    if (!ip6_isv4mapped(remoteip)) {
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
    strnum2[fmt_ulong(strnum2,maxconip)] = 0;
    if (!stralloc_copys(&tmp,"sslserver: ")) drop_nomem();
    safecats(flagdeny ? "deny" : "ok");
    cats(" "); safecats(strnum);
    cats(" "); if (localhost) safecats(localhost);
    cats(":"); safecats(localipstr);
    cats(":"); safecats(localportstr);
    cats(" "); if (remotehost) safecats(remotehost);
    cats(":"); safecats(remoteipstr);
    cats(":"); if (flagremoteinfo) safecats(tcpremoteinfo.s);
    cats(":"); safecats(remoteportstr);
    if (flagdeny == 2) { cats(" ip connection limit:"); cats(strnum2); cats(" exceeded"); }
    cats("\n");
    buffer_putflush(buffer_2,tmp.s,tmp.len);
  }

  if (flagdeny) _exit(100);

  if (gid) if (prot_gid(gid) == -1)
    logmsg(WHO,111,FATAL,"unable to set gid");
  if (uid) if (prot_uid(uid) == -1)
    logmsg(WHO,111,FATAL,"unable to set uid");

  close(pi[1]); close(po[0]); close(sslctl[0]);

  sig_uncatch(sig_child);
  sig_unblock(sig_child);
  sig_uncatch(sig_term);
  sig_uncatch(sig_pipe);

  if (fcntl(sslctl[1],F_SETFD,0) == -1)
    logmsg(WHO,111,FATAL,"unable to clear close-on-exec flag");
  strnum[fmt_ulong(strnum,sslctl[1])] = 0;
  env("SSLCTLFD",strnum);

  if (fcntl(pi[0],F_SETFD,0) == -1)
    logmsg(WHO,111,FATAL,"unable to clear close-on-exec flag");
  strnum[fmt_ulong(strnum,pi[0])] = 0;
  env("SSLREADFD",strnum);

  if (fcntl(po[1],F_SETFD,0) == -1)
    logmsg(WHO,111,FATAL,"unable to clear close-on-exec flag");
  strnum[fmt_ulong(strnum,po[1])] = 0;
  env("SSLWRITEFD",strnum);

  if (flagsslwait) {
    if (fd_copy(0,t) == -1)
      logmsg(WHO,111,FATAL,"unable to set up descriptor 0");
    if (fd_copy(1,t) == -1)
      logmsg(WHO,111,FATAL,"unable to set up descriptor 1");
  } else {
    if (fd_move(0,pi[0]) == -1)
      logmsg(WHO,111,FATAL,"unable to set up descriptor 0");
    if (fd_move(1,po[1]) == -1)
      logmsg(WHO,111,FATAL,"unable to set up descriptor 1");
  }

  if (flagkillopts) 
    socket_ipoptionskill(t);
  
  if (!flagdelay)
    socket_tcpnodelay(t);

  if (*banner) {
    buffer_init(&bo,buffer_unixwrite,1,bspace,sizeof(bspace));
    if (buffer_putsflush(&bo,banner) == -1)
      logmsg(WHO,111,FATAL,"unable to print banner");
  }

  if (!flagsslwait) {
    ssl_cmd = flagsslenv ? 'Y' : 'y';
    if (write(sslctl[1],&ssl_cmd,1) < 1)
      logmsg(WHO,111,FATAL,"unable to start TLS");
    if (flagsslenv) {
      while ((j = read(sslctl[1],envbuf,8192)) > 0) {
        stralloc_catb(&ssl_env,envbuf,j);
        if (ssl_env.len >= 2 && ssl_env.s[ssl_env.len - 2] == 0 && ssl_env.s[ssl_env.len - 1] == 0)
          break;
      }
      if (j < 0)
        logmsg(WHO,111,FATAL,"unable to read TLS environment");
      pathexec_multienv(&ssl_env);
    }
  }

  pathexec(prog);
  logmsg(WHO,111,FATAL,B("unable to run: ",*prog));
}

/* ---------------------------- parent */

void usage(void)
{
  logmsg(WHO,100,USAGE,"sslserver \
[ -1346UXpPhHrRoOdDqQvVIeEsSnNmzZ ] \
[ -c limit ] \
[ -y iprules.cdb ] \
[ -x rules.cdb ] \
[ -B banner ] \
[ -g gid ] \
[ -u uid ] \
[ -b backlog ] \
[ -l localname ] \
[ -t timeout ] \
[ -I interface ] \
[ -T ssltimeout ] \
[ -w progtimeout ] \
host port program");
}

int flag1 = 0;
int flag3 = 0;
unsigned long backlog = 20;

void printstatus(void)
{
  if (verbosity < 2) return;
  strnum[fmt_ulong(strnum,numchildren)] = 0;
  strnum2[fmt_ulong(strnum2,limit)] = 0;
  strnum3[fmt_ulong(strnum3,maxconip)] = 0;
  log_who(WHO,B("status: ",strnum,"/",strnum2,"/",strnum3));
}

static void sigterm(int dummy)
{
  _exit(0);
}

static void sigchld(int dummy)
{
  int wstat;
  int pid;

  while ((pid = wait_nohang(&wstat)) > 0) {
    if (verbosity >= 2) {
      strnum[fmt_ulong(strnum,pid + 1)] = 0;
      strnum2[fmt_ulong(strnum2,wstat)] = 0;
      log_who(WHO,B("ended by ",strnum," status ",strnum2));
    }
    if (maxconip) ipchild_clear(remoteip);
    if (numchildren) --numchildren;
    printstatus();
  }
}

void read_passwd(void) 
{
  if (!password.len) {
    buffer_init(&bo,buffer_unixread,3,bspace,sizeof(bspace));
    if (getln(&bo,&password,&match,'\0') == -1)
      logmsg(WHO,111,ERROR,"unable to read password from FD3");
    close(3);
    if (match) --password.len;
  }
}

int passwd_cb(char *buff,int size,int rwflag,void *userdata) 
{
  if (size < password.len)
    logmsg(WHO,111,ERROR,"password too long");

  byte_copy(buff,password.len,password.s);
  return password.len;
}

int main(int argc,char * const argv[]) 
{
  int opt;
  struct servent *se;
  char *x;
  unsigned long u = 0;
  int j;
  int s;
  int t;
  int ipflag = 0;

  while ((opt = getoptb(argc,(char **)argv,"1346dDvVqQhHrRUXx:y:t:T:u:g:l:b:B:c:pPoOIEeSsw:nNzZm")) != opteof)
    switch (opt) {
      case 'b': scan_ulong(optarg,&backlog); break;
      case 'c': scan_ulong(optarg,&limit); maxconip = limit; break;
      case 'X': flagallownorules = 1; break;
      case 'x': fnrules = optarg; break;
      case 'y': fniprules = optarg; break;
      case 'B': banner = optarg; break;
      case 'd': flagdelay = 1; break;
      case 'D': flagdelay = 0; break;
      case 'v': verbosity = 2; break;
      case 'V': verbosity = 3; break;
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
      case 'w': scan_uint(optarg,&progtimeout); break;
      case 'U': x = env_get("UID"); if (x) scan_ulong(x,&uid);
                x = env_get("GID"); if (x) scan_ulong(x,&gid); break;
      case 'u': scan_ulong(optarg,&uid); break;
      case 'g': scan_ulong(optarg,&gid); break;
      case 'I': netif = socket_getifidx(optarg); break;
      case 'l': localhost = optarg; break;
      case '1': flag1 = 1; break;
      case '3': flag3 = 1; break;
      case '4': ipflag = 1; break;
      case '6': ipflag = 2; break;
      case 'Z': flagclientcert = 0; break;
      case 'z': flagclientcert = 1; break;
      case 'm': flagclientcert = 2; break;
      case 'S': flagsslenv = 0; break;
      case 's': flagsslenv = 1; break;
      case 'E': flagtcpenv = 0; break;
      case 'e': flagtcpenv = 1; break;
      case 'n': flagsslwait = 1; break;
      case 'N': flagsslwait = 0; break;
      default: usage();
    }
  argc -= optind;
  argv += optind;

  if (!verbosity) buffer_2->fd = -1;

  hostname = *argv++;
  if (!hostname || (str_equal((char *)hostname,""))) usage();
  if (str_equal((char *)hostname,"0")) hostname = thishost;
  else if (str_equal((char *)hostname,":0")) {
    flagdualstack = 1;
    hostname = "::";
  }
 
  x = *argv++;
  if (!x) usage();
  prog = argv;
  if (!*argv) usage();
  if (!x[scan_ulong(x,&u)])
    localport = u;
  else {
    se = getservbyname(x,"tcp");
    if (!se)
      logmsg(WHO,111,FATAL,B("unable to figure out port number for: ",x));
    uint16_unpack_big((char *)&se->s_port,&localport);
  }

  if ((x = env_get("MAXCONIP"))) { scan_ulong(x,&u); maxconip = u; }
  if (!child_readyplus(&children,limit)) drop_nomem();

  if ((x = env_get("VERIFYDEPTH"))) { scan_ulong(x,&u); verifydepth = u; }

  if ((x = env_get("CAFILE"))) cafile = x;
  if (cafile && str_equal((char *)cafile,"")) cafile = 0;

  if ((x = env_get("CCAFILE"))) ccafile = x;
  if (ccafile && str_equal((char *)ccafile,"")) ccafile = 0;
  if (ccafile && str_equal((char*)ccafile,"-")) flagclientcert = 0;
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
      logmsg(WHO,111,FATAL,B("temporarily unable to figure out IP address for: ",(char *)hostname));

    byte_copy(localip,16,addresses.s);

    for (j = 0; j < addresses.len; j += 16) {  // Select best matching IP address
      if (ipflag == 1 && !ip6_isv4mapped(addresses.s + j)) continue;
      if (ipflag == 2 && !ip6_isv4mapped(addresses.s + j)) continue;
      byte_copy(localip,16,addresses.s + j);
    }

  }
  if (addresses.len < 16)
    logmsg(WHO,111,FATAL,B("no IP address for: ",(char *)hostname));

  if (ip6_isv4mapped(localip)) 
    s = socket_tcp4();
  else
    s = socket_tcp6();
  if (s == -1)
    logmsg(WHO,111,FATAL,"unable to create socket");

  if (ip6_isv4mapped(localip)) 
    localipstr[ip4_fmt(localipstr,localip + 12)] = 0;
  else
    localipstr[ip6_fmt(localipstr,localip)] = 0;
  localportstr[fmt_ulong(localportstr,localport)] = 0;

  if (flagdualstack) 
    socket_dualstack(s);
  if (socket_bind_reuse(s,localip,localport,netif) == -1)
    logmsg(WHO,111,FATAL,B("unable to bind to: ",localipstr," port: ",localportstr));
  if (socket_local(s,localip,&localport,&netif) == -1)
    logmsg(WHO,111,FATAL,B("unable to set local address/port: ",localipstr,"/",localportstr));
  if (socket_listen(s,backlog) == -1)
    logmsg(WHO,111,FATAL,"unable to listen");
  ndelay_off(s);

  if (flag1) {
    buffer_init(&bo,buffer_unixwrite,1,bspace,sizeof(bspace));
    buffer_puts(&bo,localipstr);
    buffer_puts(&bo," : ");
    buffer_puts(&bo,localportstr);
    buffer_puts(&bo," [");
    strnum[fmt_ulong(strnum,limit)] = 0;
    buffer_puts(&bo,strnum);
    buffer_puts(&bo,"/"); 
    strnum[fmt_ulong(strnum,maxconip)] = 0;
    buffer_puts(&bo,strnum);
    buffer_puts(&bo,"]");
    buffer_puts(&bo,"\n");
    buffer_flush(&bo);
  }

  if (flag3 == 1) read_passwd();

  ctx = ssl_server();
  ssl_errstr();
  if (!ctx) logmsg(WHO,111,FATAL,"unable to create TLS context");

  if (certchainfile) {
    switch (ssl_chainfile(ctx,certchainfile,keyfile,passwd_cb)) {
      case -1: logmsg(WHO,111,ERROR,B("unable to load certificate chain file: ",certchainfile));
      case -2: logmsg(WHO,111,ERROR,B("unable to load key: ",keyfile));
      case -3: logmsg(WHO,111,ERROR,"key does not match certificate");
      default: break;
    }
  } else {
    switch (ssl_certkey(ctx,certfile,keyfile,passwd_cb)) {
      case -1: logmsg(WHO,111,ERROR,B("unable to load certificate: ",certfile));
      case -2: logmsg(WHO,111,ERROR,B("unable to load key: ",keyfile));
      case -3: logmsg(WHO,111,ERROR,"key does not match certificate");
      default: break;
    }
  }

  if (flagclientcert) {
    if (!ssl_ca(ctx,cafile,cadir,verifydepth))
      logmsg(WHO,111,ERROR,"unable to load CA list");
    if (!ssl_cca(ctx,ccafile))
      logmsg(WHO,111,ERROR,"unable to load client CA list");
  }
  if (!ssl_params_rsa(ctx,rsalen))
    logmsg(WHO,111,ERROR,"unable to set RSA parameters");
  if (!ssl_params_dh(ctx,dhfile))
    logmsg(WHO,111,ERROR,"unable to set DH parameters");
  if (!ssl_ciphers(ctx,ciphers))
    logmsg(WHO,111,ERROR,"unable to set cipher list");

  if (verbosity >= 2) {
    strnum[fmt_ulong(strnum,getpid())] = 0;
    strnum2[fmt_ulong(strnum2,rsalen)] = 0;
    log_who(WHO,B("ciphers ",strnum," ",(char *)ciphers));
    log_who(WHO,B("cafile ",strnum," ",(char *)cafile));
    log_who(WHO,B("ccafile ",strnum," ",(char *)ccafile));
    log_who(WHO,B("cadir ",strnum," ",(char *)cadir));
    log_who(WHO,B("certchainfile ",strnum," ",(char *)certchainfile));
    log_who(WHO,B("cert ",strnum," ",(char *)certfile));
    log_who(WHO,B("key ",strnum," ",(char *)keyfile));
    log_who(WHO,B("dhparam ",strnum," ",(char *)dhfile," ",strnum2));
  }

  close(0); open_read("/dev/null");
  close(1); open_append("/dev/null");

  printstatus();

  for (;;) {
    while (numchildren >= limit) sig_pause();
    strnum[fmt_ulong(x,numchildren)] = 0;

    sig_unblock(sig_child);
    t = socket_accept(s,remoteip,&remoteport,&netif);
    sig_block(sig_child);
    if (t == -1) continue;

    if (maxconip) {
      ipchildren = ipchild_limit(remoteip,numchildren);
      if (ipchildren >= maxconip) {
        if (ip6_isv4mapped(remoteip))
          remoteipstr[ip4_fmt(remoteipstr,remoteip + 12)] = 0;
        else
          remoteipstr[ip6_fmt(remoteipstr,remoteip)] = 0;

        strnum[fmt_ulong(strnum,maxconip)] = 0;
        logmsg(WHO,100,WARN,B("ip connection limit of ",strnum," exceeded for: ",remoteipstr));
        close(t);
        continue;
      }
      ipchild_append(remoteip,numchildren); // needs to happen in parent
    }
    ++numchildren;
    printstatus();

    switch (fork()) {
      case 0:
        close(s);
        doit(t);
        logmsg(WHO,111,FATAL,B("unable to run: ",*argv));
      case -1:
        if (maxconip) ipchild_clear(remoteip); --numchildren; 
        logmsg(WHO,111,FATAL,B("unable to fork: ",strnum)); 
    }
    close(t);
  }
}
