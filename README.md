# Stage 6: authenticated ephemeral X25519 handshake (experimental)

Build (OpenSSL 3.x development headers, GCC, Linux):

```sh
gcc -Wall -Wextra -Wpedantic -Werror -O2 -pthread server.c -o server -lssl -lcrypto
gcc -Wall -Wextra -Wpedantic -Werror -O2 client.c -o client -lssl -lcrypto
```

If starting from scratch **for local testing only**, run `sh make-certs.sh` and `sh make-identities.sh`. Do not regenerate existing trusted identity keys; reuse your existing `alice.key`, `bob.key`, `alice.pub`, `bob.pub`, `ca.crt`, `server.crt`, `server.key` instead.

In three terminals:

```sh
./server server.crt server.key alice.pub bob.pub
./client localhost alice alice.key ca.crt alice.pub bob.pub
./client localhost bob bob.key ca.crt alice.pub bob.pub
```

In Alice's terminal, type `/key bob`. Bob automatically authenticates the signed ephemeral X25519 request and replies with his own signed ephemeral public key. Both print `[STAGE6] Authenticated X25519/HKDF session established ...`. Regular messages still use `bob Hello` and remain **plaintext to the relay server**.

## Security boundaries

* Stage 6 demonstrates authenticated key agreement, not encrypted messaging. It derives a 32-byte session secret in client memory and does not use or print it.
* The Ed25519 public keys must already be verified independently. X25519 public keys are signed with those identities; server forwards but cannot substitute them without detection.
* The session is volatile, one peer at a time, and does not implement key confirmation, anti-replay persistence, concurrent sessions, offline key delivery, transcript persistence, ratcheting, or secure message encryption.
* A valid previously signed INIT can be replayed by a malicious relay. A later production design must address replay and session lifecycle explicitly.
* **Not Signal, not X3DH/PQXDH, not Double Ratchet, and not production-ready.** Do not use for sensitive conversations.
