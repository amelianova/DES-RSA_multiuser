# rsa.py
import secrets
import math

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception("modular inverse not exist")
    return x % m

def is_probable_prime(n, k=8):
    if n < 2:
        return False
    small = [2,3,5,7,11,13,17,19,23]
    for p in small:
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        d//=2
        s+=1
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        comp = True
        for _ in range(s - 1):
            x = (x*x) % n
            if x == n - 1:
                comp = False
                break
        if comp:
            return False
    return True

def generate_large_prime(bits):
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(c):
            return c

def generate_rsa_keypair(bits=768):
    p = generate_large_prime(bits//2)
    q = generate_large_prime(bits//2)
    while p == q:
        q = generate_large_prime(bits//2)
    n = p * q
    phi = (p-1)*(q-1)
    e = 65537
    if math.gcd(e, phi) != 1:
        while True:
            e = secrets.randbelow(phi - 2) + 2
            if math.gcd(e, phi) == 1:
                break
    d = modinv(e, phi)
    return n, e, d

def rsa_encrypt_int(m, n, e):
    return pow(m, e, n)

def rsa_decrypt_int(c, n, d):
    return pow(c, d, n)

def hexstr_to_int(h):
    return int(h, 16)

def int_to_hexstr(i):
    return format(i, "x")
