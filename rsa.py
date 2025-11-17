# rsa.py
# RSA minimal: keygen (bits), encrypt, decrypt, helpers (Miller-Rabin, modinv)
# Tidak memakai library kriptografi eksternal.

import secrets
import math

# ---------- Math helpers ----------
def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    return x % m

def is_probable_prime(n, k=8):
    # Miller-Rabin
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    # write n-1 as d*2^s
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  # [2, n-2]
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True

def generate_large_prime(bits):
    while True:
        # ensure top bit set to get desired bit length
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate

# ---------- RSA key generation ----------
def generate_rsa_keypair(bits=1024):
    # produce p and q ~ bits/2 each
    p = generate_large_prime(bits // 2)
    q = generate_large_prime(bits // 2)
    while q == p:
        q = generate_large_prime(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    # choose e
    e = 65537
    if math.gcd(e, phi) != 1:
        # fallback choose random odd e
        while True:
            e = secrets.randbelow(phi - 2) + 2
            if math.gcd(e, phi) == 1:
                break

    d = modinv(e, phi)
    return (n, e, d)

# ---------- RSA primitive ops ----------
def rsa_encrypt_int(m_int, pub_n, pub_e):
    if m_int >= pub_n:
        raise ValueError("message integer too large for modulus")
    return pow(m_int, pub_e, pub_n)

def rsa_decrypt_int(c_int, priv_n, priv_d):
    return pow(c_int, priv_d, priv_n)

# ---------- helpers to convert hex string <-> int ----------
def hexstr_to_int(hex_str):
    return int(hex_str, 16)

def int_to_hexstr(i):
    return format(i, 'x')

# Example convenience: serialize public key for sending as string
def pubkey_to_str(n, e):
    return f"{n}:{e}"

def str_to_pubkey(s):
    parts = s.split(":")
    return (int(parts[0]), int(parts[1]))
