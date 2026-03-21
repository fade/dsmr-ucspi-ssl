cc="`head -1 ../conf-cc`"
systype="`cat systype`"

ccqlibs="`head -1 ../conf-qlibs`"
[ -d "$ccqlibs"/include ] && ccqlibs="-I${ccqlibs}/include" \
|| ccqlibs=""

cc -c trycpp.c -malign-double >/dev/null 2>&1 \
&& ccad="-malign-double"

cc -c trycpp.c -march=ultrasparc >/dev/null 2>&1 \
&& ccus="-march=ultrasparc"

cc -c trycpp.c -march=powerpc >/dev/null 2>&1 \
&& ccpp="-march=powerpc"

cc -c trycpp.c -march=21164 >/dev/null 2>&1 \
&& cc21="-march=21164"

cc -c trycpp.c -march=native >/dev/null 2>&1 \
&& ccarm="-march=native"

rm -f trycpp.o

ccssl="`head -1 ../conf-ssl`"
eval cc -c tryssl.c ${ccssl} >/dev/null 2>&1 \
|| ccssl=""

ccbase="cc -fomit-frame-pointer -Wall"

case "$cc:$systype" in
  auto:*:i386-*:*)
    cc="$ccbase -O1 $ccad"
    ;;
  auto:*:amd64-*:*)
    cc="$ccbase -O2 $ccad"
    ;;
  auto:*:x86_64-*:*)
    cc="$ccbase -O2 $ccad"
    ;;
  auto:*:sparc-*:*:*:*)
    cc="$ccbase -O1 $ccus"
    ;;
  auto:*:ppc-*:*:*:*)
    cc="$ccbase -O2 $ccpp"
    ;;
  auto:*:alpha-*:*:*:*)
    cc="$ccbase -O2 $cc21"
    ;;
  auto:aix-*:-:-:*:-)
    cc="$ccbase -O2 $ccpp"
    ;;
  auto:*:armv7l-:*)
    cc="$ccbase -O2 $ccarm"
    ;;
  auto:*)
    cc="$ccbase -O2"
    ;;
esac

cat warn-auto.sh
echo exec "$cc" ${ccqlibs} ${ccssl} '-c ${1+"$@"}'
