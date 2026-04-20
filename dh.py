# Maysa Khanfar 1221623
# Lara Foqaha 1220071

import hashlib
import secrets

def dh_generate_private(p):
    # Generate a random private exponent in [2, p-2].
    if p <= 5:
        raise ValueError("p too small")
    return secrets.randbelow(p - 3) + 2  # 2..p-2

def dh_public(g, priv, p):
    # Compute public value, g^priv mod p
    if not (2 <= g < p):
        raise ValueError("bad g")
    if not (2 <= priv <= p - 2):
        raise ValueError("bad priv")
    return pow(g, priv, p)

def dh_shared(their_pub, my_priv, p):
    # Compute shared secret as integer
    if not (2 <= their_pub <= p - 2):
        raise ValueError("bad peer public value")
    if not (2 <= my_priv <= p - 2):
        raise ValueError("bad my_priv")
    return pow(their_pub, my_priv, p)

def int_to_bytes(x):
    # Done cuz hash functions work on bytes
    if x < 0:
        raise ValueError("negative int")
    if x == 0:
        return b"\x00"
    length = (x.bit_length() + 7) // 8
    return x.to_bytes(length, "big")

def derive_session_key_from_shared(shared_s):
    s_bytes = int_to_bytes(shared_s)
    return hashlib.sha256(s_bytes).digest()[:16]
