#!/bin/sh
# Post-deploy smoke check for the share-links Worker.
# Usage: ./smoke.sh <base-url>   e.g. ./smoke.sh https://share.tinycloud.xyz
# Checks that creating a link answers 410 gone, and that an unknown id answers the uniform 404
# without CORS headers. Needs curl. Prints no tokens, ciphertext, or response bodies.
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <base-url>" >&2
  exit 2
fi

BASE="${1%/}/api/share-links"
umask 077
WORK="$(mktemp -d -p /var/tmp)"
chmod 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

code="$(curl -sS -D "$WORK/create.headers" -o "$WORK/create.json" -w '%{http_code}' -X POST "$BASE" \
  -H 'Content-Type: application/json' --data '{}')"
[ "$code" = "410" ] || fail "POST expected 410, got $code"
[ "$(cat "$WORK/create.json")" = '{"error":"gone"}' ] || fail "POST body is not the gone body"
echo "ok: POST -> 410 gone"

code="$(curl -sS -D "$WORK/nf.headers" -o "$WORK/nf.json" -w '%{http_code}' "$BASE/aaaaaaaaaaaaaaaaaaaaaaaaaa")"
[ "$code" = "404" ] || fail "GET unknown id expected 404, got $code"
[ "$(cat "$WORK/nf.json")" = '{"error":"not_found"}' ] || fail "GET unknown id body is not the uniform 404"
if grep -qi '^access-control-' "$WORK/nf.headers"; then
  fail "404 returned a CORS header"
fi
echo "ok: GET unknown id -> 404 uniform"
echo "smoke passed"
