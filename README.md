# Stage 8 — Automatic E2EE session setup (C/OpenSSL)

This is an **experimental prototype**, not an independently audited messenger. Do not use for sensitive communications. Sessions are held in memory; there is no offline delivery, persistent ratchet state, crash recovery, or authenticated delivery acknowledgement. The server must have both users connected; queued messages are held only in client RAM. This release supports one peer session per client process.

## Build and tests

```sh
./test_all.sh
```

The test script builds with `-Wall -Wextra -Werror`, runs the standalone Double Ratchet tests, and exercises live TLS/Ed25519/X25519 messaging in both directions, including first-message automatic key exchange and `-d` diagnostics.

## Run

Generate credentials using `make-certs.sh` and `make-identities.sh`, then start the server:

```sh
./server server.crt server.key alice.pub bob.pub
```

In two terminals:

```sh
./client localhost alice alice.key ca.crt alice.pub bob.pub
./client localhost bob bob.key ca.crt alice.pub bob.pub
```

Send `bob Hello` from Alice or `alice Hello` from Bob. The initial X25519 handshake, internal encrypted bootstrap, and subsequent DH ratchet transitions are automatic. A small queue holds up to 16 messages (up to 1200 bytes each) during session setup; this queue is **not persistent**. The first queued message is sent after handshake completion, and a recipient's first outgoing message works after the encrypted bootstrap arrives. There is no plaintext fallback.

To see protocol diagnostics, run either client with `-d`:

```sh
./client -d localhost alice alice.key ca.crt alice.pub bob.pub
```

`-d` logs automatic `/key` operations and `/rekey`-equivalent DH ratchet events. Neither command is accepted as a user command. Normal operation suppresses these diagnostics. `QUIT` ends the session.

## Limitations

This is **not** the full Signal protocol. No X3DH/PQXDH, prekey server, offline delivery, multi-device support, disk-backed state, durable outgoing queue, exactly-once delivery, or security audit. Both clients must be connected and each client only supports one peer at a time. Simultaneous first-contact initiation and disconnect/reconnect recovery are not guaranteed. Do not treat `SENT` as a recipient delivery acknowledgement.

## Terminal input fix (November 9)
- Normal mode suppresses ambiguous `SENT` lines; `-d` reports relay acceptance, explicitly not delivery confirmation.
- Backspace deletes complete UTF-8 codepoints (e.g., `ş`), rather than leaving invalid bytes in outgoing text.
- ASCII control characters are ignored on input and rejected on authenticated incoming plaintext to prevent terminal escape injection.
- Messages remain limited to 1200 bytes. Delivery acknowledgments, persistence, and offline recovery are not implemented.
