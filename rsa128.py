# Maysa Khanfar 1221623
# Lara Foqaha 1220071 


import hashlib
import secrets

def egcd(a: int, b: int):
    # Extended Euclidean Algorithm, returns (g, x, y) such that ax + by = g = gcd(a,b)
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a: int, n: int) -> int:
    # Modular inverse, a^{-1} mod n
    g, x, _ = egcd(a, n)
    if g != 1:
        raise ValueError("no modular inverse")
    return x % n

#  Primality testing (Miller–Rabin) 
def is_probable_prime(n: int, s: int = 12) -> bool:

    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # n - 1 = 2^u * r  (r odd)
    r = n - 1
    u = 0
    while r % 2 == 0:
        r //= 2
        u += 1

    for _ in range(s):
        a = secrets.randbelow(n - 3) + 2   # 2 .. n-2
        z = pow(a, r, n)

        if z != 1 and z != n - 1:
            for _ in range(u - 1):
                z = pow(z, 2, n)
                if z == 1:
                    return False
                if z == n - 1:
                    break
            if z != n - 1:
                return False

    return True

def generate_prime(bits: int) -> int:
    # Generate a probable prime
    if bits < 16:
        raise ValueError("bits too small")
    while True:
        # ensure top bit set and odd
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate

# RSA core

def rsa_generate_keypair_128(e: int = 65537):
    # Generate RSA-128 keypair, returns (n, e, d)

    # two 64-bit primes -> 128-bit modulus
    p = generate_prime(64)
    q = generate_prime(64)
    while q == p:
        q = generate_prime(64)

    n = p * q
    phi = (p - 1) * (q - 1)

    if phi % e == 0:
        # rare, regenerate
        return rsa_generate_keypair_128(e=e)

    d = modinv(e, phi)
    return (n, e, d)

def hash_to_int(msg: bytes) -> int:
    # SHA-256(msg) interpreted as big-endian integer
    return int.from_bytes(hashlib.sha256(msg).digest(), "big")

def rsa_sign(msg: bytes, n: int, d: int) -> int:
    # Sign: sig = (H(msg) mod n)^d mod n , returns signature as integer.

    if n <= 0 or d <= 0:
        raise ValueError("bad key")
    h = hash_to_int(msg) % n
    return pow(h, d, n)

def rsa_verify(msg: bytes, sig: int, n: int, e: int) -> bool:
    # Verify: (sig^e mod n) == (H(msg) mod n)

    if n <= 0 or e <= 0:
        return False
    if sig < 0 or sig >= n:
        return False
    h = hash_to_int(msg) % n
    return pow(sig, e, n) == h

