host=${1-0}
path=${2-}
port=${3-443}
args=""
if [ $# -gt 3 ]
then
  shift; shift; shift
  args="$@"
fi
echo "GET /${path} HTTP/1.1
Host: $host:$port
" | sslclient -XRHl0 $args -- "$host" "$port" sh -c '
  addcr >&7
  exec delcr <&6
' | awk '/^$/ { body=1; next } { if (body) print }'
