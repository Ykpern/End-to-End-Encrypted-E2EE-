"""
SecureChat client. See crypto_utils.py for the underlying crypto design.

Usage:
    python client.py --host 127.0.0.1 --port 5555 --name Alice
    python client.py --host 127.0.0.1 --port 5555 --name Bob
"""

import argparse
import socket
import struct
import sys
import threading

import crypto_utils as crypto


def send_frame(sock: socket.socket, data: bytes):
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_exact(sock: socket.socket, n: int):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_frame(sock: socket.socket):
    header = recv_exact(sock, 4)
    if header is None:
        return None
    length = struct.unpack(">I", header)[0]
    return recv_exact(sock, length)


def handshake(sock: socket.socket):
    """
    Exchange ephemeral X25519 public keys, then derive this session's
    send/receive chain keys from the ECDH shared secret.
    """
    private_key, public_key = crypto.generate_ephemeral_keypair()
    my_pub_bytes = crypto.public_key_to_bytes(public_key)
    send_frame(sock, my_pub_bytes)

    peer_pub_bytes = recv_frame(sock)
    if peer_pub_bytes is None:
        raise ConnectionError("peer disconnected during handshake")

    peer_public_key = crypto.public_key_from_bytes(peer_pub_bytes)
    root_key = crypto.derive_root_key(private_key, peer_public_key)

    # Both sides need to agree, without extra messages, on who is the
    # "initiator" purely so they label the two chains consistently. Which
    # side is picked has no security meaning -- comparing the raw public
    # key bytes just gives both peers the same answer without needing a
    # separate round trip.
    is_initiator = my_pub_bytes < peer_pub_bytes
    return crypto.derive_chains(root_key, is_initiator)


def receiver_loop(sock: socket.socket, recv_chain_holder: list, name: str):
    while True:
        frame = recv_frame(sock)
        if frame is None:
            print(f"\n[{name}] peer disconnected.")
            sys.exit(0)

        message_key, recv_chain_holder[0] = crypto.ratchet_step(recv_chain_holder[0])
        try:
            plaintext = crypto.decrypt(message_key, frame)
            print(f"\nthem: {plaintext.decode()}\n{name}> ", end="", flush=True)
        except Exception:
            print(
                f"\n[{name}] received a message that failed authentication -- discarding.\n{name}> ",
                end="",
                flush=True,
            )


def main():
    parser = argparse.ArgumentParser(description="SecureChat client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5555)
    parser.add_argument("--name", default="me")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((args.host, args.port))
    print(f"[{args.name}] connected. Performing key exchange...")

    send_chain, recv_chain = handshake(sock)
    print(f"[{args.name}] secure channel established. Type a message and press Enter (Ctrl+C to quit).\n")

    recv_chain_holder = [recv_chain]
    threading.Thread(
        target=receiver_loop, args=(sock, recv_chain_holder, args.name), daemon=True
    ).start()

    send_chain_holder = [send_chain]
    while True:
        try:
            text = input(f"{args.name}> ")
        except (EOFError, KeyboardInterrupt):
            break
        if not text:
            continue
        message_key, send_chain_holder[0] = crypto.ratchet_step(send_chain_holder[0])
        send_frame(sock, crypto.encrypt(message_key, text.encode()))

    sock.close()


if __name__ == "__main__":
    main()
