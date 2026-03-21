/* what to do */
#include "readwrite.h"
#include "exit.h"
#include "buffer.h"

char bspace[BUFFER_SMALL];
buffer b = BUFFER_INIT(buffer_unixwrite,1,bspace,sizeof(bspace));

static void outs(const char *s)
{
 if (buffer_puts(&b,s) == -1) _exit(111);
}

int main(int argc,char **argv)
{
  char *name;
  char *value;
  unsigned char ch;
  char octal[4];

  name = argv[1];
  if (!name) _exit(100);
  value = argv[2];
  if (!value) _exit(100);

  outs("const char ");
  outs(name);
  outs("[] = \"\\\n");

  while ((ch = *value++)) {
    outs("\\");
    octal[3] = 0;
    octal[2] = '0' + (ch & 7); ch >>= 3;
    octal[1] = '0' + (ch & 7); ch >>= 3;
    octal[0] = '0' + (ch & 7);
    outs(octal);
  }

  outs("\\\n\";\n");
  if (buffer_flush(&b) == -1) _exit(111);
  _exit(0);
}
