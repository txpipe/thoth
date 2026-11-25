#!/usr/bin/env bash
# Regenerate the test CA and server certificate the live check serves HTTPS with.
# They are test-only: the key is committed, so never trust this CA outside tests.
set -euo pipefail
out="$(cd "$(dirname "$0")/../test/fixtures" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$work/ca.key"
openssl req -x509 -new -nodes -key "$work/ca.key" -sha256 -days 36500 \
  -subj "/O=Thoth test/CN=Thoth test root" -out "$work/ca.crt"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$out/server.key"
openssl req -new -key "$out/server.key" -subj "/O=Thoth test/CN=test-server.thoth" -out "$work/server.csr"
printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nsubjectAltName=DNS:test-server.thoth\n' \
  > "$work/ext.cnf"
openssl x509 -req -in "$work/server.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" -CAcreateserial \
  -days 36500 -sha256 -extfile "$work/ext.cnf" -out "$out/server.crt"
openssl x509 -in "$work/ca.crt" -outform der -out "$out/root_ca.der"
