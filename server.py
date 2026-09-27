"""
SecureChat relay server.

This server is deliberately "trustless": it never sees a private key,
performs no cryptographic operations, and only forwards length-prefixed,
opaque byte frames between exactly two connected clients. Even a fully
compromised server operator cannot read the conversation, because all
encryption and decryption happens on the clients.

Usage:
    python server.py --port 5555
"""

import argparse
import socket
import threading


def recv_exact(sock: socket.socket, n: int):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def relay_one_direction(src: socket.socket, dst: socket.socket):
    try:
        while True:
            length_prefix = recv_exact(src, 4)
            if length_prefix is None:
                break
            length = int.from_bytes(length_prefix, "big")
            payload = recv_exact(src, length)
            if payload is None:
                break
            dst.sendall(length_prefix + payload)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle_pair(conn_a: socket.socket, conn_b: socket.socket):
    t1 = threading.Thread(target=relay_one_direction, args=(conn_a, conn_b), daemon=True)
    t2 = threading.Thread(target=relay_one_direction, args=(conn_b, conn_a), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    conn_a.close()
    conn_b.close()
    print("[server] pair disconnected")


def main():
    parser = argparse.ArgumentParser(description="SecureChat blind relay server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5555)
    args = parser.parse_args()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((args.host, args.port))
    server_sock.listen(4)
    print(f"[server] listening on {args.host}:{args.port}")

    while True:
        print("[server] waiting for a pair of clients...")
        conn_a, addr_a = server_sock.accept()
        print(f"[server] client connected from {addr_a}, waiting for its peer")
        conn_b, addr_b = server_sock.accept()
        print(f"[server] client connected from {addr_b} -- pairing and relaying (blind)")
        threading.Thread(target=handle_pair, args=(conn_a, conn_b), daemon=True).start()


if __name__ == "__main__":
    main()
