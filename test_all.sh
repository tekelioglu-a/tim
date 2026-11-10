#!/bin/sh
set -eu
cd "$(dirname "$0")"
gcc -Wall -Wextra -Wpedantic -Werror -O2 -pthread server.c -o server -lssl -lcrypto
gcc -Wall -Wextra -Wpedantic -Werror -O2 client.c -o client -lssl -lcrypto
gcc -Wall -Wextra -Wpedantic -Werror -O2 test_ratchet.c -o test_ratchet -lssl -lcrypto
./test_ratchet
python3 test_network.py
python3 test_restart.py
