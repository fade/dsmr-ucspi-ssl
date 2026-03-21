#ifndef IP_BIT_H
#define IP_BIT_H

#include "stralloc.h"

extern int bitstring_ip4(stralloc *,stralloc *);
extern int ip4_bitstring(stralloc *,char *,unsigned int);
extern unsigned int ip4_cscan(const char *,char [4]);
extern void getnum(char *,int,unsigned long *);

extern int bitstring_ip6(stralloc *,stralloc *);
extern int ip6_bitstring(stralloc *,char *,unsigned int);
extern unsigned int ip6_fmt_str(stralloc *,char *);

#endif
