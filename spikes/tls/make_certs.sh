#!/bin/bash
# Throwaway test PKI for the TLS spike (T0): a CA and a server certificate
# for "localhost" and 127.0.0.1, ECDSA P-256, made with the environment's
# openssl CLI. Usage: make_certs.sh <dir>
set -euo pipefail
d=$1
mkdir -p "$d"
cd "$d"
openssl ecparam -name prime256v1 -genkey -noout -out ca.key 2>/dev/null
openssl req -x509 -new -key ca.key -days 2 -subj "/CN=mojo_net T0 test CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out ca.pem 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out server.key 2>/dev/null
openssl req -new -key server.key -subj "/CN=localhost" -out server.csr 2>/dev/null
printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\n" > server.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 \
  -extfile server.ext -out server.pem 2>/dev/null
# A second, unrelated CA: its trust must not make server.pem valid.
openssl ecparam -name prime256v1 -genkey -noout -out other_ca.key 2>/dev/null
openssl req -x509 -new -key other_ca.key -days 2 -subj "/CN=unrelated CA" -out other_ca.pem 2>/dev/null
echo "certs in $d"
