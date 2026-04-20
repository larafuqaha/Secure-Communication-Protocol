# Maysa Khanfar 1221623
# Lara Foqaha 1220071 

import socket
import struct

from crypto import cbc_decrypt
from dh import (
    dh_generate_private,
    dh_public,
    dh_shared,
    derive_session_key_from_shared,
)
from rsa128 import (
    rsa_generate_keypair_128,
    rsa_sign,
    rsa_verify,
)

# ---------------- CONFIG ----------------
HOST = "127.0.0.1"
PORT = 5005

SERVER_ID = "1220071"
CLIENT_ID_EXPECTED = 1220071  

# ---------------- DH PARAMETERS ----------------
DH_P = int("F7E75FDC469067FFDC4E847C51F452DF", 16)  
DH_G = 2

# ---------------- TCP HELPERS ----------------

def recv_exact(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data += chunk
    return data

def recv_message(conn):
    header = recv_exact(conn, 4)
    (length,) = struct.unpack(">I", header)
    return recv_exact(conn, length)

def send_message(conn, data):
    header = struct.pack(">I", len(data))
    conn.sendall(header + data)

# ---------------- PACK / UNPACK ----------------

def pack_u16(x):
    return struct.pack(">H", x)

def unpack_u16(b, off):
    return struct.unpack_from(">H", b, off)[0], off + 2

def pack_bytes(blob):
    if len(blob) > 65535:
        raise ValueError("blob too long for u16 length")
    return pack_u16(len(blob)) + blob

def unpack_bytes(b, off):
    ln, off = unpack_u16(b, off)
    return b[off:off + ln], off + ln

def pack_str(s):
    return pack_bytes(s.encode("utf-8"))

def unpack_str(b, off):
    blob, off = unpack_bytes(b, off)
    return blob.decode("utf-8", errors="strict"), off

def int_to_min_bytes(x):
    if x < 0:
        raise ValueError("negative int")
    if x == 0:
        return b"\x00"
    ln = (x.bit_length() + 7) // 8
    return x.to_bytes(ln, "big")

def pack_int(x):
    return pack_bytes(int_to_min_bytes(x))

def unpack_int(b, off):
    blob, off = unpack_bytes(b, off)
    return int.from_bytes(blob, "big"), off

# ---------------- MESSAGE TYPES ----------------
TYPE_CLIENT_HELLO = 0x01
TYPE_SERVER_HELLO = 0x02
TYPE_DATA  = 0x03

# ---------------- HANDSHAKE HELPERS ----------------

def sign_dh_value(student_id, dh_pub):
    return student_id.encode("utf-8") + b"|" + int_to_min_bytes(dh_pub)

def parse_client_hello(data):
    if not data or data[0] != TYPE_CLIENT_HELLO:
        raise ValueError("expected CLIENT_HELLO")
    off = 1
    client_id, off = unpack_str(data, off)
    nC, off = unpack_int(data, off)
    eC, off = unpack_int(data, off)
    A,  off = unpack_int(data, off)
    sigA, off = unpack_int(data, off)
    if off != len(data):
        raise ValueError("extra bytes in CLIENT_HELLO")
    return client_id, nC, eC, A, sigA

def build_server_hello(server_id, n, e, B, sigB):
    payload = bytes([TYPE_SERVER_HELLO])
    payload += pack_str(server_id)
    payload += pack_int(n)
    payload += pack_int(e)
    payload += pack_int(B)
    payload += pack_int(sigB)
    return payload

def do_handshake(conn):
    # Server side handshake:
    # Create RSA key pair
    # Receive client's DH value and check its signature
    # Generate server DH value and sign it
    # Send server response
    # Compute shared secret and session key

    nS, eS, dS = rsa_generate_keypair_128()

    # Receive client's hello
    data = recv_message(conn)
    client_id, nC, eC, A, sigA = parse_client_hello(data)
    print("[server] got CLIENT_HELLO from:", client_id)

    if CLIENT_ID_EXPECTED is not None and client_id != CLIENT_ID_EXPECTED:
        raise ValueError("unexpected client_id")

    # Verify client signature on A
    msgA = sign_dh_value(client_id, A)

    if not rsa_verify(msgA, sigA, nC, eC):
        raise ValueError("BAD CLIENT SIGNATURE")
    print("[server] client signature OK")

    b = dh_generate_private(DH_P)
    B = dh_public(DH_G, b, DH_P)

    # Sign B
    msgB = sign_dh_value(SERVER_ID, B)
    sigB = rsa_sign(msgB, nS, dS)

    # Send server hello
    send_message(conn, build_server_hello(SERVER_ID, nS, eS, B, sigB))
    print("[server] sent SERVER_HELLO")

    # Shared secret + session key
    s_int = dh_shared(A, b, DH_P)
    session_key = derive_session_key_from_shared(s_int)
    print("[server] session key:", session_key.hex())

    return session_key


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"[server] listening on {HOST}:{PORT}")

    conn, addr = s.accept()
    print("[server] connected from", addr)

    try:
        # Phase 2 handshake
        session_key = do_handshake(conn)

        # Receive encrypted DATA messages
        while True:
            try:
                data = recv_message(conn)
            except ConnectionError:
                print("[server] client disconnected")
                break

            if not data:
                conn.sendall(b"ERROR")
                continue

            msg_type = data[0]
            if msg_type != TYPE_DATA:
                print("[server] unexpected msg type:", msg_type)
                conn.sendall(b"ERROR")
                continue

            if len(data) < 1 + 16:
                print("[server] invalid DATA length")
                conn.sendall(b"ERROR")
                continue

            iv = data[1:17]
            ciphertext = data[17:]

            try:
                plaintext = cbc_decrypt(ciphertext, session_key, iv)
                print("[server] decrypted:",
                      plaintext.decode("utf-8", errors="replace"))
                conn.sendall(b"OK")
            except Exception as e:
                print("[server] decrypt error:", e)
                conn.sendall(b"ERROR")

    finally:
        conn.close()
        s.close()

if __name__ == "__main__":
    main()
