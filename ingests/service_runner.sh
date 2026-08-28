
if [ -z "$1" ]; then
  echo "Usage: $0 <python_script> [args...]" >&2
  exit 2
fi

SCRIPT="$1"
shift

while true; do
  python3 "$SCRIPT" "$@"
  code=$?
  echo "crashed with code $code — restarting in 10s" >&2
  sleep 10
done

