# TLS 1.3 + Ed25519 identity-authentication prototype

Build (Linux, OpenSSL 3.x development headers):

    gcc -Wall -Wextra -Wpedantic -O2 -pthread server.c -o server -lssl -lcrypto
    gcc -Wall -Wextra -Wpedantic -O2 client.c -o client -lssl -lcrypto

Generate TLS certificates and **local test identities**:

    chmod +x make-certs.sh make-identities.sh
    ./make-certs.sh
    ./make-identities.sh

Start server:

    ./server server.crt server.key alice.pub bob.pub

Start clients (separate terminals):

    ./client localhost alice alice.key ca.crt
    ./client localhost bob bob.key ca.crt

Send messages using `bob Hello` or `alice Hello`. Use `QUIT` to disconnect.

## Authentication protocol

1. Client sends `HELLO username` inside verified TLS.
2. Server generates a fresh 32-byte cryptographically random nonce and sends `CHALLENGE <hex nonce>`.
3. Client signs the byte string `messenger-auth-v1\\0` + UTF-8 username bytes + 32-byte nonce using its Ed25519 private key, sends `AUTH <hex signature>`.
4. Server verifies the signature against the **pre-provisioned** public key for the named user. No password is sent.

## Security limits

- This is **authentication**, not end-to-end encryption. Server still reads all message plaintext.
- Public identity keys are installed on the server in advance, not accepted on first contact. A compromised server can still misrepresent users to other users until peer identity verification and E2E encryption are added.
- Generate identity keys on each real client's own device. Never upload or distribute client private keys to the server. This test script generates both locally solely for demonstration.
- The server's TLS private key is distinct from the clients' Ed25519 identity private keys.
- Not production ready: TLS handshakes are blocking without timeouts; server has no persistent queues, account management, revocation, key rotation, DoS protections or complete TLS nonblocking-state-machine hardening. Keep the test server on localhost/trusted network.
- A successful `SENT` means queued for an online connection, not cryptographically acknowledged or stored persistently.
