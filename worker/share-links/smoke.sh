#!/bin/sh
# Post-deploy smoke check for the share-links Worker.
# Usage: ./smoke.sh <base-url>   e.g. ./smoke.sh https://share.tinycloud.xyz
# Creates one link with a one-hour TTL, checks GET headers and bytes, checks a
# wrong-token DELETE and the uniform 404, deletes the link, and checks the 404
# after delete. Needs curl. Prints no tokens, ciphertext, or response bodies.
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <base-url>" >&2
  exit 2
fi

BASE="${1%/}/api/share-links"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

# $1 = header file, $2 = case-insensitive ERE matched at line start, $3 = label
expect_header() {
  grep -qiE "^$2" "$1" || fail "$3"
}

# $1 = label, remaining args = curl arguments; expects the uniform 404 body
expect_not_found() {
  label="$1"
  shift
  code="$(curl -sS -o "$WORK/nf.json" -w '%{http_code}' "$@")"
  [ "$code" = "404" ] || fail "$label: expected 404, got $code"
  [ "$(cat "$WORK/nf.json")" = '{"error":"not_found"}' ] || fail "$label: body is not the uniform 404"
  echo "ok: $label -> 404 uniform"
}

PLAIN='smoke-test-bytes-0001'
printf '%s' "$PLAIN" > "$WORK/plain.bin"
CIPHER="$(printf '%s' "$PLAIN" | base64 | tr '+/' '-_' | tr -d '=\n')"
EXPIRES="$(node -e 'console.log(new Date(Date.now() + 3600e3).toISOString())')"

# POST
code="$(curl -sS -o "$WORK/create.json" -w '%{http_code}' -X POST "$BASE" \
  -H 'Content-Type: application/json' \
  --data "{\"ciphertext\":\"$CIPHER\",\"expiresAt\":\"$EXPIRES\"}")"
[ "$code" = "201" ] || fail "POST expected 201, got $code"
ID="$(sed -n 's/.*"id":"\([a-z2-7]*\)".*/\1/p' "$WORK/create.json")"
TOKEN="$(sed -n 's/.*"deleteToken":"\([A-Za-z0-9_-]*\)".*/\1/p' "$WORK/create.json")"
[ -n "$ID" ] || fail "POST response has no id"
[ -n "$TOKEN" ] || fail "POST response has no deleteToken"
echo "ok: POST 201 (id and deleteToken present)"

# GET: header set and raw bytes
code="$(curl -sS -D "$WORK/get.headers" -o "$WORK/get.bin" -w '%{http_code}' "$BASE/$ID")"
[ "$code" = "200" ] || fail "GET expected 200, got $code"
expect_header "$WORK/get.headers" 'content-type: application/octet-stream' 'GET content-type is not application/octet-stream'
expect_header "$WORK/get.headers" 'content-disposition: attachment' 'GET content-disposition is not attachment'
expect_header "$WORK/get.headers" 'x-content-type-options: nosniff' 'GET nosniff missing'
expect_header "$WORK/get.headers" 'x-share-cid: bafkrei' 'GET X-Share-Cid missing'
expect_header "$WORK/get.headers" 'cache-control: no-store' 'GET no-store missing'
if grep -qi '^access-control-' "$WORK/get.headers"; then
  fail "GET returned a CORS header"
fi
cmp -s "$WORK/get.bin" "$WORK/plain.bin" || fail "GET body differs from the stored bytes"
echo "ok: GET 200 with octet-stream, attachment, nosniff, X-Share-Cid, no CORS, exact bytes"

# DELETE with a wrong token: uniform 404, record kept
WRONG="$(printf '%043d' 0 | tr 0 x)"
expect_not_found "DELETE wrong token" -X DELETE -H "Authorization: Bearer $WRONG" "$BASE/$ID"

# DELETE with the right token: 204
code="$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE \
  -H "Authorization: Bearer $TOKEN" "$BASE/$ID")"
[ "$code" = "204" ] || fail "DELETE expected 204, got $code"
echo "ok: DELETE 204"

# GET after delete: uniform 404
expect_not_found "GET after delete" "$BASE/$ID"

# GET unknown id: same uniform 404
expect_not_found "GET unknown id" "$BASE/aaaaaaaaaaaaaaaaaaaaaaaaaa"

echo "smoke: all checks passed"
