# Stage 7: Experimental E2EE text messages

**Educational prototype only. Not Signal Double Ratchet and not production secure.**

Build on Linux with OpenSSL 3 development headers:

```sh
gcc -Wall -Wextra -Wpedantic -Werror -O2 -pthread server.c -o server -lssl -lcrypto
gcc -Wall -Wextra -Wpedantic -Werror -O2 client.c -o client -lssl -lcrypto
```

For a fresh *local test only* run `sh make-certs.sh` and `sh make-identities.sh`. **Never regenerate an existing user's identity keys**; copy the existing trusted identity files instead.

Run in three terminals:

```sh
./server server.crt server.key alice.pub bob.pub
./client localhost alice alice.key ca.crt alice.pub bob.pub
./client localhost bob bob.key ca.crt alice.pub bob.pub
```

Alice types `/key bob`, waits for `[STAGE6] ... session established`, then types `bob Hello Bob!`. Bob sees `[E2EE VERIFIED alice] ... Hello Bob!` and can respond with `alice Hello Alice!`.

Messages are encrypted client-side using AES-256-GCM and signed with Ed25519. The server sees `E7:counter:nonce:tag:ciphertext` rather than plaintext. Each direction derives a new 32-byte message key and advances its chain after successful processing. AES-GCM additionally authenticates sender, recipient, timestamp and counter as associated data. The TLS 1.3 layer remains in place.

## Important limitations

* This is a **sequential, in-memory, single-peer demonstration**, not Signal's Double Ratchet. No ongoing DH ratchet, offline delivery, skipped-key storage, durable replay protection, or post-compromise recovery.
* The signed X25519 handshake from Stage 6 lacks durable replay protection and explicit key confirmation. A malicious relay can replay handshake requests, with possible session resets and denial of service. No asynchronous prekeys.
* Reordering, message loss, reconnection, simultaneous initiation, and multiple devices/sessions are **not handled safely**. A lost message desynchronizes the chain. The relay may fan out to multiple devices, which this demo cannot support.
* Keys are in process memory; device capture, malicious endpoints, compromised identity keys, and traffic metadata remain threats. The server can block, reorder and replay traffic, and can see participants and ciphertext lengths.
* Only `alice` and `bob` are supported. Text messages are limited to approximately 1200 bytes, and plaintext is not padded. No attachments or media.
* The proposed separate X25519-derived XOR-pad layer has **not** been implemented.
* No independent audit, fuzzing campaign, formal protocol review, or production hardening has been performed. Do not use for sensitive conversations.
