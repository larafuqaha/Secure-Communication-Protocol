# Maysa Khanfar 1221623
# Lara Foqaha 1220071 

import socket
import struct

from crypto import (
    cbc_encrypt,
    derive_reference_iv,
    iv_from_reference,
)
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

# ---------------- connection ----------------
HOST = "127.0.0.1"
PORT = 5005

CLIENT_ID = "1220071"
SERVER_ID_EXPECTED = 1220071  

# ---------------- DH parameters ----------------
DH_P = int("F7E75FDC469067FFDC4E847C51F452DF", 16) 
DH_G = 2

# ---------------- TCP helpers ----------------

def send_message(sock, data: bytes):
    header = struct.pack(">I", len(data))
    sock.sendall(header + data)

def recv_exact(sock, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data += chunk
    return data

def recv_message(sock) -> bytes:
    header = recv_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    return recv_exact(sock, length)

# ---------------- PACK / UNPACK ----------------

def pack_u16(x: int) -> bytes:
    return struct.pack(">H", x)

def unpack_u16(b: bytes, off: int):
    return struct.unpack_from(">H", b, off)[0], off + 2

def pack_bytes(blob: bytes) -> bytes:
    if len(blob) > 65535:
        raise ValueError("blob too long for u16 length")
    return pack_u16(len(blob)) + blob

def unpack_bytes(b: bytes, off: int):
    ln, off = unpack_u16(b, off)
    return b[off:off + ln], off + ln

def pack_str(s: str) -> bytes:
    return pack_bytes(s.encode("utf-8"))

def unpack_str(b: bytes, off: int):
    blob, off = unpack_bytes(b, off)
    return blob.decode("utf-8", errors="strict"), off

def int_to_min_bytes(x: int) -> bytes:
    if x < 0:
        raise ValueError("negative int")
    if x == 0:
        return b"\x00"
    ln = (x.bit_length() + 7) // 8
    return x.to_bytes(ln, "big")

def pack_int(x: int) -> bytes:
    return pack_bytes(int_to_min_bytes(x))

def unpack_int(b: bytes, off: int):
    blob, off = unpack_bytes(b, off)
    return int.from_bytes(blob, "big"), off

# ---------------- MESSAGE TYPES ----------------
TYPE_CLIENT_HELLO = 0x01
TYPE_SERVER_HELLO = 0x02
TYPE_DATA         = 0x03

# ---------------- HANDSHAKE HELPERS ----------------

def sign_dh_value(student_id: str, dh_pub: int) -> bytes:
    # This is the byte message that rsa_sign/rsa_verify will hash internally
    return student_id.encode("utf-8") + b"|" + int_to_min_bytes(dh_pub)

def build_client_hello(client_id: str, n: int, e: int, A: int, sigA: int) -> bytes:
    payload = bytes([TYPE_CLIENT_HELLO])
    payload += pack_str(client_id)
    payload += pack_int(n)
    payload += pack_int(e)
    payload += pack_int(A)
    payload += pack_int(sigA)
    return payload

def parse_server_hello(data: bytes):
    if not data or data[0] != TYPE_SERVER_HELLO:
        raise ValueError("expected SERVER_HELLO")
    off = 1
    server_id, off = unpack_str(data, off)
    nS, off = unpack_int(data, off)
    eS, off = unpack_int(data, off)
    B,  off = unpack_int(data, off)
    sigB, off = unpack_int(data, off)
    if off != len(data):
        raise ValueError("extra bytes in SERVER_HELLO")
    return server_id, nS, eS, B, sigB

def do_handshake(sock) -> bytes:
    # Client handshake:
    # create RSA key pair
    # generate DH value
    # sign and send client DH
    # receive server DH
    # verify server signature
    # derive session key


    nC, eC, dC = rsa_generate_keypair_128()

    a = dh_generate_private(DH_P)
    A = dh_public(DH_G, a, DH_P)

    # Sign A
    msgA = sign_dh_value(CLIENT_ID, A)
    sigA = rsa_sign(msgA, nC, dC)

    # Send CLIENT_HELLO
    send_message(sock, build_client_hello(CLIENT_ID, nC, eC, A, sigA))
    print("[client] sent CLIENT_HELLO")

    # Receive SERVER_HELLO
    resp = recv_message(sock)
    server_id, nS, eS, B, sigB = parse_server_hello(resp)
    print("[client] got SERVER_HELLO from:", server_id)

    if SERVER_ID_EXPECTED is not None and server_id != SERVER_ID_EXPECTED:
        raise ValueError("unexpected server_id")

    # Verify server signature
    msgB = sign_dh_value(server_id, B)
    if not rsa_verify(msgB, sigB, nS, eS):
        raise ValueError("BAD SERVER SIGNATURE")
    print("[client] server signature OK")

    # Shared secret + session key
    s_int = dh_shared(B, a, DH_P)
    session_key = derive_session_key_from_shared(s_int)
    print("[client] session key:", session_key.hex())

    return session_key



def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    print("[client] connected")

    # Phase 2 handshake
    session_key = do_handshake(s)

    ref_iv = derive_reference_iv(CLIENT_ID)
    iv_counter = 0

    while True:
        message = input("\nEnter message to send (or q to quit): ")
        if message.lower() == "q":
            break

        plaintext = message.encode("utf-8")

        iv = iv_from_reference(ref_iv, iv_counter)
        iv_counter += 1

        ciphertext = cbc_encrypt(plaintext, session_key, iv)

        payload = bytes([TYPE_DATA]) + iv + ciphertext
        send_message(s, payload)

        print("[client] sent DATA")
        print("IV:", iv.hex())
        print("Ciphertext:", ciphertext.hex())

        ack = s.recv(1024)
        print("[client] server replied:", ack.decode(errors="replace"))

    s.close()

if __name__ == "__main__":
    main()
