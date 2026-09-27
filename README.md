# SecureChat — End-to-End Encrypted Messaging

A trustless, end-to-end encrypted chat application: the relay server never
sees a private key and cannot read any message content, even if it were
fully compromised.

## How it works

- **Key exchange:** each client generates a fresh, single-use **X25519**
  keypair per session and exchanges raw public keys with its peer through
  the relay. The relay only forwards opaque, length-prefixed byte frames —
  it never has access to a private key or plaintext.
- **Key derivation:** the ECDH shared secret is stretched with
  **HKDF-SHA256** into a root key, which is split into two independent
  chain keys — one per direction (A→B, B→A).
- **Perfect forward secrecy:** every message advances its chain one step
  via a symmetric ratchet — HKDF derives the one-time message key *and*
  the next chain key from the current chain key, and the old chain key is
  discarded. Because the ratchet only runs forward, compromising a later
  chain key can never expose earlier messages.
- **Encryption:** every message is encrypted individually with
  **AES-256-GCM** under its own one-time key, giving both confidentiality
  and integrity — tampered or replayed frames fail authentication and are
  dropped rather than displayed.

## Tech stack

Python 3, the `cryptography` library (X25519, HKDF, AES-GCM), raw TCP
sockets, threading.

## Usage

Start the relay:

```bash
python server.py --port 5555
```

Connect two clients (in separate terminals):

```bash
python client.py --host 127.0.0.1 --port 5555 --name Alice
python client.py --host 127.0.0.1 --port 5555 --name Bob
```

Type a message in either terminal and press Enter — it's encrypted on the
sending client, relayed blind through the server, and decrypted on the
receiving client.

## Design notes / limitations

This is a two-party, single-session demonstration of ECDH key agreement
plus symmetric-ratchet forward secrecy, built to explore the core ideas
behind protocols like Signal's Double Ratchet. It intentionally does not
implement:

- **Identity/authentication of the peer** — there's no protection against
  an active man-in-the-middle on the very first connection, since public
  keys are trusted on first exchange with no out-of-band verification.
- **Out-of-order or dropped-message handling** — a production ratchet
  keeps a window of skipped-message keys; this one assumes messages
  arrive in order.
- **Multi-device or group chat support.**
- **Persistent storage** — all keys live only in memory and are gone as
  soon as the process exits.

## Requirements

```bash
pip install cryptography
```
