host=${1-0}
port=${2-465}
args=""
if [ $# -gt 2 ]
then
  shift; shift
  args="$@"
fi
exec sslclient -XRHl0 $args -- "$host" "$port" mconnect-io
