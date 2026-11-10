#!/bin/sh
set -eu
umask 077
for user in alice bob; do
  if [ -e "$user.key" ] || [ -e "$user.pub" ]; then
    echo "Refusing to overwrite $user identity" >&2
    exit 1
  fi
  openssl genpkey -algorithm ED25519 -out "$user.key"
  openssl pkey -in "$user.key" -pubout -out "$user.pub"
done
printf 'Generated Alice and Bob identity key pairs. Keep *.key private.\n'
