#!/bin/bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 IMAGE OUTPUT_DIRECTORY" >&2
  exit 2
fi

image=$1
output=$2
project_root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d /private/tmp/openepm-packaged-metadata.XXXXXX)
container=""
server_pid=""

cleanup() {
  if [[ -n $server_pid ]]; then kill "$server_pid" 2>/dev/null || true; fi
  if [[ -n $container ]]; then docker rm -f "$container" >/dev/null 2>&1 || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

container=$(docker create "$image")
mkdir -p "$work/app"
docker cp "$container:/srv/openepm/web/app/." "$work/app"
docker rm "$container" >/dev/null
container=""

# The packaged web server mounts index.html at / and the Vite assets below
# /ui/assets. Reproduce that public layout exactly in the disposable server.
mkdir -p "$work/web/ui"
cp "$work/app/index.html" "$work/web/index.html"
cp -R "$work/app/assets" "$work/web/ui/assets"

python3 -m http.server 4174 --bind 127.0.0.1 --directory "$work/web" \
  >"$work/http.log" 2>&1 &
server_pid=$!
for _ in {1..50}; do
  if curl --fail --silent http://127.0.0.1:4174/ >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work/http.log" >&2
    exit 1
  fi
  sleep 0.1
done
curl --fail --silent --show-error http://127.0.0.1:4174/ >/dev/null

mkdir -p "$output"
openepm_node_path=$(npm root -g)
NODE_PATH="$openepm_node_path" node \
  "$project_root/scripts/qualify_react_visual_regression.cjs" \
  --base-url=http://127.0.0.1:4174 \
  --browser-channel=chrome \
  --metadata-scale=true \
  --routes=metadata \
  --output="$output"
