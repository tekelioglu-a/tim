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

## Stage 8G — Experimental delivery receipts

Messages now carry random 128-bit identifiers inside the encrypted payload. The receiver sends an encrypted delivery acknowledgement only after successfully authenticating and decrypting the message. Sender displays `[QUEUED]` and `[DELIVERED]` with the first eight hexadecimal digits of the identifier. The complete identifier is 128 bits.

A pending encrypted frame is retransmitted after 3 seconds, at most 5 total transmissions. The receiver remembers the most recent 128 message IDs and ciphertext hashes, and resends acknowledgements for recognized duplicate frames without displaying duplicate messages. Pending frames and duplicate caches are **memory-only**.

**Important limitations:** Initial KEY INIT/REPLY and internal bootstrap frames have no retransmission or acknowledgement yet. No offline store-and-forward, persistent session recovery, delivery after a process restart, or durable exactly-once semantics. A delivery receipt means the recipient client decrypted the message, not that the human read it. Once retry limits are exhausted, a message is marked UNCONFIRMED, not definitively undelivered. Do not use for sensitive production communication without independent security review.

## Receipt cleanup update

Acknowledged and retry-exhausted receipt slots are wiped with `OPENSSL_cleanse` before reuse. A full 32-slot receipt queue produces an explicit `[QUEUE FULL]` warning and does not transmit the new message. Flushed plaintext pending-queue slots are also wiped. All queue data remains memory-only; there is no persistence across restarts.

## Complete-package setup

This archive includes `make-certs.sh`, `make-identities.sh`, and `message_crypto.h`, which were omitted from the preceding ZIP.

```sh
./build.sh
./make-certs.sh
./make-identities.sh
./server server.crt server.key alice.pub bob.pub
```

Start clients in separate terminals:

```sh
./client localhost alice alice.key ca.crt alice.pub bob.pub
./client localhost bob bob.key ca.crt alice.pub bob.pub
```

Generate the development credentials only once. `make-identities.sh` intentionally refuses to overwrite existing identities. Do not distribute private `.key` files.

## Reconnection handling (Stage 8H)
When the relay reports `ERR User not connected` or `ERR Peer not connected`, the client marks outstanding receipts `[UNCONFIRMED]`, wipes the old volatile ratchet and clears pending messages. The next message to the peer automatically initiates a new authenticated X25519 `/key` exchange; `/rekey` is not appropriate for a lost session. Messages from the old session are **not** resent. A reconnect by itself does not notify the sender; the next attempted send triggers the new exchange. This prototype still has no durable state or authenticated presence protocol.

## Three-hour delivery acknowledgement window
Outstanding messages are retried every 60 seconds for up to 3 hours from the initial transmission while both clients remain connected. If no end-to-end acknowledgement arrives by then, the sender reports `[UNCONFIRMED]` and erases the receipt. If the relay explicitly reports that the recipient is offline, outstanding receipts are marked unconfirmed immediately, as in Stage 8H. The queue has 32 slots and is memory-only; closing the client discards it. These changes do not add offline message storage or guarantee delivery. The three-hour expiry path has not been tested with a real three-hour wait.

The bracketed `[E2EE VERIFIED ...]` prefix is local terminal output, not part of the encrypted plaintext. The protocol timestamp is signed and included in authenticated message processing; it is not a nonce.

### Compact delivery display (normal mode)

In normal mode, successful E2EE verification is silent. Received messages
show the authenticated sender on the timestamp line and the message text on
the next line, for example:

```text
2026-11-10T12:44:46Z [Bob]
hi
```

A failed signature/ratchet check still reports a rejection. Sending prints
`|* |  17db8983` when queued, `|**|  17db8983` on acknowledgement, and
`|*é|  17db8983` when delivery fails or expires. The eight hexadecimal
digits identify the same message across status lines. These are separate
status lines, not in-place rewrites. Use `-d` for detailed receipt and
verification messages. Debug verification appears on its own line above
the timestamp and message.


### Volatile sensitive-buffer erasure

The client calls `OPENSSL_cleanse()` on outgoing plaintext payloads after encryption,
received plaintext after processing (including error/duplicate paths), typed
commands after dispatch, queued plaintext after sending or cancellation, and
session/receipt state on shutdown. Ratchet temporary material is cleared as
soon as no longer needed. AEAD decryption failure clears the output buffer.

**Limitations:** This is best-effort buffer erasure, not a guarantee against
swap, hibernation, crash dumps, terminal scrollback, or copies inside OpenSSL
or other libraries. Memory locking and OS-specific protections are deferred.
The relay receives ciphertext, not plaintext.
