#!/bin/sh
set -eu
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
  -keyout ca.key -out ca.crt -subj '/CN=Messenger Development CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'
openssl req -newkey rsa:2048 -sha256 -nodes \
  -keyout server.key -out server.csr -subj '/CN=localhost'
cat > server.ext <<'EXT'
subjectAltName=DNS:localhost,IP:127.0.0.1
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
EXT
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 30 -sha256 -extfile server.ext
chmod 600 ca.key server.key
printf 'Generated ca.crt, server.crt and server.key\n'
