#!/usr/bin/env bash
# Build a lab-only amd64 debug image for one PHP 8.5 tag.
#
# Why not `docker build`? This Docker install has no buildx, and the legacy
# builder ignores --platform, so FROM resolves to the arm64 variant on Apple
# Silicon. We instead build inside a pinned amd64 container and commit it.
#
# Usage:
#   research/build_85_debug.sh <pinned-base-ref> <target-tag>
#
# Example:
#   research/build_85_debug.sh \
#     php:8.5.11-apache@sha256:47e6d8849049375e0d19e81f1b391ed88828d4653e0d1b00822185b66b564e8b \
#     php2shell:8.5.11-debug
set -euo pipefail

base="${1:?pinned base ref, e.g. php:8.5.11-apache@sha256:...}"
tag="${2:?target tag, e.g. php2shell:8.5.11-debug}"
root="$(cd "$(dirname "$0")/.." && pwd)"
name="p2s85-build-$$"

cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run -d --platform linux/amd64 --name "$name" "$base" tail -f /dev/null >/dev/null
docker exec "$name" sh -c 'uname -m'
docker exec "$name" sh -c \
  'apt-get update -qq >/dev/null && apt-get install -y -qq --no-install-recommends gdb procps >/dev/null && mkdir -p /usr/src/php/ext'
docker cp "$root/research/85probe" "$name:/usr/src/php/ext/p2s85probe"
docker exec "$name" sh -c '
  set -e
  cd /usr/src/php/ext/p2s85probe
  phpize >/dev/null
  ./configure --enable-p2s85probe >/dev/null
  make -j"$(nproc)" >/dev/null
  make install >/dev/null
  printf "extension=p2s85probe.so\n" > /usr/local/etc/php/conf.d/zz-p2s85probe.ini
  gcc -shared -fPIC -O2 -Wall -o /usr/local/lib/p2s85-preload.so p2s85-preload.c -ldl
  php -m | grep -q p2s85probe
'
docker commit --change 'ENV P2S85_LOG=/out/p2s85-probe.log' "$name" "$tag" >/dev/null
docker image inspect "$tag" --format '{{.Id}} {{.Os}}/{{.Architecture}}'
