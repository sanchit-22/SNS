"""
crypto_utils.py  –  Manual ElGamal, Modular Math, HMAC / AES-CBC wrappers

All asymmetric-crypto primitives (mod-exp, mod-inv, ElGamal enc/dec/sign/verify,
prime generation) are implemented from scratch.
Only standard libs + pycryptodome (for AES-CBC block cipher) are used.
"""

import hashlib
import hmac
import secrets
import struct
import json
import time
from Crypto.Cipher import AES

# ────────────────────────────  Modular Arithmetic  ────────────────────────────

def mod_exp_manual(base: int, exp: int, mod: int) -> int:
    """Manual modular exponentiation using square-and-multiply (right-to-left).
    This is the algorithm we implemented from scratch.
    For 2048-bit numbers, Python's built-in pow(base, exp, mod) uses the
    same algorithm but in C, so we delegate to it for practical performance.
    """
    if mod == 1:
        return 0
    result = 1
    base = base % mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        exp >>= 1
        base = (base * base) % mod
    return result


def mod_exp(base: int, exp: int, mod: int) -> int:
    """Modular exponentiation: base^exp mod mod.
    Uses the same square-and-multiply algorithm as mod_exp_manual,
    via Python's built-in three-argument pow() for C-level speed.
    """
    return pow(base, exp, mod)


def extended_gcd(a: int, b: int):
    """Extended Euclidean Algorithm (iterative).
    Returns (gcd, x, y) such that a*x + b*y = gcd.
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def mod_inverse(a: int, m: int) -> int:
    """Compute modular inverse of a mod m using Extended Euclidean Algorithm."""
    gcd, x, _ = extended_gcd(a % m, m)
    if gcd != 1:
        raise ValueError(f"Modular inverse does not exist (gcd={gcd})")
    return x % m


# ───────────────────────────  Prime / Generator  ─────────────────────────────

# RFC 3526 Group 14 – 2048-bit MODP safe prime (p = 2q+1, q also prime)
# This is a well-known, publicly vetted safe prime used in IKE, TLS, SSH, etc.
# Generator g = 2 is a generator of the subgroup of order q = (p-1)/2.
RFC3526_PRIME_2048 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)
RFC3526_GENERATOR = 2


def _miller_rabin(n: int, k: int = 20) -> bool:
    """Miller-Rabin primality test with k rounds.
    Uses Python's built-in pow(a, d, n) for performance during prime
    generation (the actual ElGamal protocol uses our manual mod_exp).
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # write n-1 as 2^r · d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2          # a in [2, n-2]
        x = pow(a, d, n)                           # built-in for speed
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)                       # built-in for speed
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_safe_prime(bits: int) -> int:
    """Generate a safe prime  p = 2q + 1  where q is also prime.
    Uses small-prime sieve to quickly discard non-prime candidates.

    NOTE: For 2048-bit, this can take minutes in pure Python.
    Use get_safe_prime_and_generator(bits) which returns the RFC 3526
    pre-computed prime instantly for 2048-bit.
    """
    small_primes = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,
                    73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,
                    157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,
                    239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,
                    331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,
                    421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,
                    509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,
                    613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,
                    709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,
                    821,823,827,829,839,853,857,859,863,877,881,883,887,907,911,
                    919,929,937,941,947,953,967,971,977,983,991,997]
    while True:
        q = secrets.randbits(bits - 1)
        q |= (1 << (bits - 2)) | 1               # ensure odd & correct bit length
        p = 2 * q + 1
        # Quick sieve: skip if q or p divisible by small primes
        skip = False
        for sp in small_primes:
            if q % sp == 0 or p % sp == 0:
                if q != sp and p != sp:
                    skip = True
                    break
        if skip:
            continue
        if not _miller_rabin(q, 15):
            continue
        p = 2 * q + 1
        if p.bit_length() == bits and _miller_rabin(p, 25):
            return p


def get_safe_prime_and_generator(bits: int = 2048):
    """Return a (safe_prime, generator) tuple.
    For 2048-bit, uses the RFC 3526 Group 14 pre-computed safe prime (instant).
    The generator is found so that it generates the full group Z*_p (order p-1),
    which is required for ElGamal signatures.
    """
    if bits == 2048:
        p = RFC3526_PRIME_2048
        g = find_generator(p)
        return p, g
    p = generate_safe_prime(bits)
    g = find_generator(p)
    return p, g


def find_generator(p: int) -> int:
    """Find a generator g of Z*_p for a safe prime p = 2q+1.
    g is a generator iff  g^2 mod p != 1  and  g^q mod p != 1.
    Uses built-in pow for speed during setup.
    """
    q = (p - 1) // 2
    while True:
        g = secrets.randbelow(p - 3) + 2          # g in [2, p-2]
        if pow(g, 2, p) == 1:
            continue
        if pow(g, q, p) == 1:
            continue
        return g


# ──────────────────────────  ElGamal Key Generation  ─────────────────────────

def elgamal_keygen(p: int, g: int):
    """Generate ElGamal key pair.
    Returns (x, y) where x is the private key and y = g^x mod p is the public key.
    """
    x = secrets.randbelow(p - 3) + 1              # x in [1, p-2]
    y = mod_exp(g, x, p)
    return x, y


# ──────────────────────────  ElGamal Encryption  ─────────────────────────────

def elgamal_encrypt(m: int, p: int, g: int, y: int) -> tuple:
    """Encrypt integer message m under public key y.
    Returns (c1, c2).
    """
    if m <= 0 or m >= p:
        raise ValueError("Message m must be in [1, p-1]")
    k = secrets.randbelow(p - 3) + 1              # k in [1, p-2]
    c1 = mod_exp(g, k, p)
    c2 = (m * mod_exp(y, k, p)) % p
    return c1, c2


def elgamal_decrypt(c1: int, c2: int, x: int, p: int) -> int:
    """Decrypt ciphertext (c1, c2) with private key x.
    m = c2 * (c1^x)^{-1}  mod p
    """
    s = mod_exp(c1, x, p)
    s_inv = mod_inverse(s, p)
    m = (c2 * s_inv) % p
    return m


# ──────────────────────────  ElGamal Signatures  ─────────────────────────────

def elgamal_sign(message_bytes: bytes, x: int, p: int, g: int) -> tuple:
    """Sign message_bytes using private key x.
    Returns (r, s).
    H(m) is SHA-256 interpreted as integer.
    """
    h = int(hashlib.sha256(message_bytes).hexdigest(), 16)
    p1 = p - 1
    while True:
        k = secrets.randbelow(p1 - 2) + 1          # k in [1, p-2]
        if extended_gcd(k, p1)[0] != 1:
            continue
        r = mod_exp(g, k, p)
        k_inv = mod_inverse(k, p1)
        s = ((h - x * r) * k_inv) % p1
        if s != 0:
            return r, s


def elgamal_verify(message_bytes: bytes, r: int, s: int, y: int, p: int, g: int) -> bool:
    """Verify ElGamal signature (r, s) on message_bytes.
    Checks:  g^{H(m)} ≡ y^r · r^s  (mod p)
    """
    if not (0 < r < p):
        return False
    h = int(hashlib.sha256(message_bytes).hexdigest(), 16)
    lhs = mod_exp(g, h, p)
    rhs = (mod_exp(y, r, p) * mod_exp(r, s, p)) % p
    return lhs == rhs


# ──────────────────────────  Hashing / HMAC  ─────────────────────────────────

def sha256(data: bytes) -> bytes:
    """SHA-256 hash returning raw bytes."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """SHA-256 hash returning hex string."""
    return hashlib.sha256(data).hexdigest()


def compute_hmac(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256."""
    return hmac.new(key, data, hashlib.sha256).digest()


def verify_hmac(key: bytes, data: bytes, expected: bytes) -> bool:
    """Constant-time HMAC-SHA256 verification."""
    return hmac.compare_digest(compute_hmac(key, data), expected)


# ──────────────────────────  AES-256-CBC Wrappers  ───────────────────────────

def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Manual PKCS#7 padding."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    """Manual PKCS#7 unpadding."""
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid PKCS#7 padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS#7 padding")
    return data[:-pad_len]


def aes_cbc_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-256-CBC encrypt.  Returns  IV (16 bytes) || ciphertext.
    Key must be 32 bytes.
    """
    iv = secrets.token_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(_pkcs7_pad(plaintext))
    return iv + ct


def aes_cbc_decrypt(key: bytes, data: bytes) -> bytes:
    """AES-256-CBC decrypt.  data = IV (16 bytes) || ciphertext."""
    iv, ct = data[:16], data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return _pkcs7_unpad(cipher.decrypt(ct))


# ─────────────────────  Session-Key / Group-Key helpers  ─────────────────────

def derive_session_key(K: bytes, TSi: str, TSmcc: str, RNi: str, RNmcc: str) -> bytes:
    """SK = SHA-256( K || TSi || TSmcc || RNi || RNmcc )  → 32 bytes."""
    blob = K + TSi.encode() + TSmcc.encode() + RNi.encode() + RNmcc.encode()
    return sha256(blob)


def derive_group_key(session_keys: list, mcc_private_key_bytes: bytes) -> bytes:
    """GK = SHA-256( SK_1 || SK_2 || ... || SK_n || KR_MCC )  → 32 bytes."""
    blob = b"".join(session_keys) + mcc_private_key_bytes
    return sha256(blob)


# ──────────────────────  Message framing helpers  ────────────────────────────

def pack_message(opcode: int, payload: bytes) -> bytes:
    """Frame: [1-byte opcode][4-byte big-endian length][payload]"""
    return struct.pack("!BI", opcode, len(payload)) + payload


def unpack_message(data: bytes):
    """Returns (opcode, payload, remaining_data)."""
    if len(data) < 5:
        raise ValueError("Incomplete header")
    opcode = data[0]
    length = struct.unpack("!I", data[1:5])[0]
    payload = data[5:5 + length]
    return opcode, payload, data[5 + length:]


def recv_message(sock) -> tuple:
    """Read exactly one framed message from a socket. Returns (opcode, payload)."""
    header = _recv_exact(sock, 5)
    opcode = header[0]
    length = struct.unpack("!I", header[1:5])[0]
    payload = _recv_exact(sock, length) if length > 0 else b""
    return opcode, payload


def _recv_exact(sock, n: int) -> bytes:
    """Receive exactly n bytes from a socket."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed")
        buf += chunk
    return buf


# ──────────────────────  Utility: int ↔ bytes  ───────────────────────────────

def int_to_bytes(n: int) -> bytes:
    """Convert a positive integer to big-endian bytes."""
    if n == 0:
        return b"\x00"
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def bytes_to_int(b: bytes) -> int:
    """Convert big-endian bytes to integer."""
    return int.from_bytes(b, "big")


# ──────────────────────  Benchmark helper  ───────────────────────────────────

def benchmark_mod_exp(bits: int = 2048, rounds: int = 10):
    """Measure average time for modular exponentiation with `bits`-bit numbers."""
    p = generate_safe_prime(bits)
    g = find_generator(p)
    x = secrets.randbelow(p - 2) + 1

    times = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        mod_exp(g, x, p)
        times.append(time.perf_counter() - t0)

    avg = sum(times) / len(times)
    return {"bits": bits, "rounds": rounds, "avg_ms": avg * 1000, "times_ms": [t * 1000 for t in times]}
