#!/bin/sh
set -eu
cd "$(dirname "$0")"
gcc -Wall -Wextra -Wpedantic -Werror -O2 -pthread server.c -o server -lssl -lcrypto
gcc -Wall -Wextra -Wpedantic -Werror -O2 client.c -o client -lssl -lcrypto
printf 'Built server and client.\n'
