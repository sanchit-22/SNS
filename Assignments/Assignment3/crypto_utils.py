"""
crypto_utils.py — Core cryptographic primitives for Kerberos multi-signature system.

Implements:
  - Modular arithmetic (square-and-multiply exponentiation)
  - Schnorr key generation, signing, verification
  - AES-256-CBC encryption/decryption
  - Manual PKCS#7 padding
  - Schnorr group parameter generation
  - Colorful logging utilities
"""

import hashlib
import os
import json
import secrets
import struct
import time
import sys

# ─── Colorful Logging ─────────────────────────────────────────────────────────

class Colors:
    """ANSI color codes for terminal output."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BG_RED     = "\033[41m"
    BG_GREEN   = "\033[42m"
    BG_YELLOW  = "\033[43m"
    BG_BLUE    = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN    = "\033[46m"

def log_info(tag, message):
    """Log informational message in cyan."""
    ts = time.strftime("%H:%M:%S")
    print(f"{Colors.CYAN}[{ts}] {Colors.BOLD}[{tag}]{Colors.RESET} {Colors.CYAN}ℹ {message}{Colors.RESET}")

def log_success(tag, message):
    """Log success message in green."""
    ts = time.strftime("%H:%M:%S")
    print(f"{Colors.GREEN}[{ts}] {Colors.BOLD}[{tag}]{Colors.RESET} {Colors.GREEN}✔ {message}{Colors.RESET}")

def log_warning(tag, message):
    """Log warning message in yellow."""
    ts = time.strftime("%H:%M:%S")
    print(f"{Colors.YELLOW}[{ts}] {Colors.BOLD}[{tag}]{Colors.RESET} {Colors.YELLOW}⚠ {message}{Colors.RESET}")

def log_error(tag, message):
    """Log error message in red."""
    ts = time.strftime("%H:%M:%S")
    print(f"{Colors.RED}[{ts}] {Colors.BOLD}[{tag}]{Colors.RESET} {Colors.RED}✖ {message}{Colors.RESET}")

def log_crypto(tag, message):
    """Log cryptographic operation in magenta."""
    ts = time.strftime("%H:%M:%S")
    print(f"{Colors.MAGENTA}[{ts}] {Colors.BOLD}[{tag}]{Colors.RESET} {Colors.MAGENTA}🔐 {message}{Colors.RESET}")

def log_network(tag, message):
    """Log network activity in blue."""
    ts = time.strftime("%H:%M:%S")
    print(f"{Colors.BLUE}[{ts}] {Colors.BOLD}[{tag}]{Colors.RESET} {Colors.BLUE}🌐 {message}{Colors.RESET}")

def log_attack(tag, message):
    """Log attack scenario in red with background."""
    ts = time.strftime("%H:%M:%S")
    print(f"{Colors.BG_RED}{Colors.WHITE}[{ts}] [{tag}] 🚨 {message}{Colors.RESET}")

def log_attack_result(passed, message):
    """Log attack test result."""
    if passed:
        print(f"  {Colors.GREEN}✔ PASS: {message}{Colors.RESET}")
    else:
        print(f"  {Colors.RED}✖ FAIL: {message}{Colors.RESET}")

def log_header(title):
    """Print a bold header banner."""
    line = "═" * (len(title) + 6)
    print(f"\n{Colors.BOLD}{Colors.CYAN}╔{line}╗")
    print(f"║   {title}   ║")
    print(f"╚{line}╝{Colors.RESET}\n")

def log_separator():
    """Print a visual separator."""
    print(f"{Colors.CYAN}{'─' * 60}{Colors.RESET}")


# ─── Modular Arithmetic ──────────────────────────────────────────────────────

def mod_exp(base, exp, mod):
    """
    Modular exponentiation using square-and-multiply.
    Computes (base^exp) mod mod.
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


def mod_inverse(a, m):
    """
    Compute modular inverse of a mod m using Extended Euclidean Algorithm.
    Returns x such that (a * x) mod m == 1.
    """
    if a < 0:
        a = a % m
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist for a={a}, m={m}")
    return x % m


def _extended_gcd(a, b):
    """Extended Euclidean Algorithm. Returns (gcd, x, y) such that a*x + b*y = gcd."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = _extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


# ─── Schnorr Parameter Generation ────────────────────────────────────────────

def _is_probable_prime(n, k=20):
    """Miller-Rabin primality test with k rounds."""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = mod_exp(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = mod_exp(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_schnorr_params(bit_length=512):
    """
    Generate Schnorr group parameters (p, q, g).
    - q is a prime of bit_length bits
    - p = 2q + 1 is a safe prime
    - g is a generator of the subgroup of order q
    """
    log_crypto("KEYGEN", f"Generating {bit_length}-bit Schnorr parameters (p, q, g)...")

    while True:
        # Generate a random prime q
        q = secrets.randbits(bit_length) | (1 << (bit_length - 1)) | 1
        if not _is_probable_prime(q):
            continue
        p = 2 * q + 1
        if _is_probable_prime(p):
            break

    # Find generator g of subgroup of order q
    while True:
        h = secrets.randbelow(p - 3) + 2
        g = mod_exp(h, 2, p)  # g = h^((p-1)/q) mod p = h^2 mod p for safe prime
        if g > 1:
            break

    log_success("KEYGEN", f"Generated Schnorr params: p ({p.bit_length()} bits), q ({q.bit_length()} bits)")
    return p, q, g


# ─── Schnorr Key Generation ──────────────────────────────────────────────────

def schnorr_keygen(p, q, g):
    """
    Generate a Schnorr key pair.
    Returns (private_key x, public_key y) where y = g^x mod p.
    """
    x = secrets.randbelow(q - 1) + 1  # x ∈ [1, q-1]
    y = mod_exp(g, x, p)
    return x, y


# ─── Schnorr Signature ───────────────────────────────────────────────────────

def schnorr_sign(message, x, p, q, g, authority_id):
    """
    Generate a Schnorr signature for a message.

    Args:
        message: bytes or str — the message to sign
        x: int — private key
        p, q, g: Schnorr group parameters
        authority_id: str — identity of the signing authority

    Returns:
        (R, s, authority_id) where R = g^k mod p, s = k + e*x mod q
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    if isinstance(authority_id, str):
        authority_id_bytes = authority_id.encode('utf-8')
    else:
        authority_id_bytes = authority_id

    # Fresh random nonce — CRITICAL: must never be reused
    k = secrets.randbelow(q - 1) + 1

    # Commitment
    R = mod_exp(g, k, p)

    # Challenge: e = H(m || R || authority_id)
    R_bytes = R.to_bytes((R.bit_length() + 7) // 8, 'big')
    hash_input = message + R_bytes + authority_id_bytes
    e = int(hashlib.sha256(hash_input).hexdigest(), 16) % q

    # Response
    s = (k + e * x) % q

    return R, s, authority_id


def schnorr_verify(message, R, s, y, p, q, g, authority_id):
    """
    Verify a Schnorr signature.

    Args:
        message: bytes or str — the original message
        R: int — commitment
        s: int — response
        y: int — public key of the signer
        p, q, g: Schnorr group parameters
        authority_id: str — identity of the signing authority

    Returns:
        True if signature is valid, False otherwise
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    if isinstance(authority_id, str):
        authority_id_bytes = authority_id.encode('utf-8')
    else:
        authority_id_bytes = authority_id

    # Recompute challenge
    R_bytes = R.to_bytes((R.bit_length() + 7) // 8, 'big')
    hash_input = message + R_bytes + authority_id_bytes
    e = int(hashlib.sha256(hash_input).hexdigest(), 16) % q

    # Verify: g^s ≡ R * y^e mod p
    lhs = mod_exp(g, s, p)
    rhs = (R * mod_exp(y, e, p)) % p

    return lhs == rhs


def verify_multi_signatures(message, signatures, public_keys, p, q, g, threshold=2):
    """
    Verify that at least `threshold` independent Schnorr signatures are valid.

    Args:
        message: bytes or str — the signed message
        signatures: list of (R, s, authority_id) tuples
        public_keys: dict mapping authority_id → public key y
        p, q, g: Schnorr group parameters
        threshold: minimum number of valid signatures required

    Returns:
        (is_valid: bool, valid_count: int, details: list)
    """
    valid_count = 0
    details = []

    for R, s, auth_id in signatures:
        if auth_id not in public_keys:
            details.append((auth_id, False, "Unknown authority"))
            continue
        y = public_keys[auth_id]
        valid = schnorr_verify(message, R, s, y, p, q, g, auth_id)
        if valid:
            valid_count += 1
            details.append((auth_id, True, "Valid"))
        else:
            details.append((auth_id, False, "Invalid signature"))

    return valid_count >= threshold, valid_count, details


# ─── PKCS#7 Padding (Manual Implementation) ──────────────────────────────────

def pkcs7_pad(data, block_size=16):
    """Apply PKCS#7 padding to data."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data):
    """Remove PKCS#7 padding from data."""
    if len(data) == 0:
        raise ValueError("Cannot unpad empty data")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError(f"Invalid padding length: {pad_len}")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS#7 padding")
    return data[:-pad_len]


# ─── AES-256-CBC ──────────────────────────────────────────────────────────────

def _xor_bytes(a, b):
    """XOR two byte strings of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))


def _aes_encrypt_block(block, key):
    """
    AES single block encryption using Python's built-in (via cryptography lib for AES-ECB only).
    We implement CBC mode manually, only using a library for the raw AES block cipher.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    enc = cipher.encryptor()
    return enc.update(block) + enc.finalize()


def _aes_decrypt_block(block, key):
    """AES single block decryption."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    dec = cipher.decryptor()
    return dec.update(block) + dec.finalize()


def aes_encrypt(plaintext, key):
    """
    AES-256-CBC encryption with manual PKCS#7 padding.

    Args:
        plaintext: bytes or str
        key: 32 bytes (256-bit key)

    Returns:
        bytes: IV (16 bytes) + ciphertext
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if len(key) != 32:
        raise ValueError(f"AES-256 requires a 32-byte key, got {len(key)}")

    iv = os.urandom(16)
    padded = pkcs7_pad(plaintext)

    ciphertext = b""
    prev_block = iv
    for i in range(0, len(padded), 16):
        block = padded[i:i+16]
        xored = _xor_bytes(block, prev_block)
        encrypted = _aes_encrypt_block(xored, key)
        ciphertext += encrypted
        prev_block = encrypted

    return iv + ciphertext


def aes_decrypt(ciphertext_with_iv, key):
    """
    AES-256-CBC decryption with PKCS#7 unpadding.

    Args:
        ciphertext_with_iv: bytes — IV (first 16 bytes) + ciphertext
        key: 32 bytes (256-bit key)

    Returns:
        bytes: decrypted plaintext
    """
    if len(key) != 32:
        raise ValueError(f"AES-256 requires a 32-byte key, got {len(key)}")
    if len(ciphertext_with_iv) < 32:
        raise ValueError("Ciphertext too short (must contain IV + at least one block)")

    iv = ciphertext_with_iv[:16]
    ciphertext = ciphertext_with_iv[16:]

    plaintext = b""
    prev_block = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted = _aes_decrypt_block(block, key)
        plaintext += _xor_bytes(decrypted, prev_block)
        prev_block = block

    return pkcs7_unpad(plaintext)


# ─── Key & Config Helpers ────────────────────────────────────────────────────

def generate_session_key():
    """Generate a random 256-bit session key for AES."""
    return os.urandom(32)


def save_keys_to_file(filepath, data):
    """Save key data to a JSON file."""
    # Convert bytes to hex strings for JSON serialization
    serializable = _make_serializable(data)
    with open(filepath, 'w') as f:
        json.dump(serializable, f, indent=2)


def load_keys_from_file(filepath):
    """Load key data from a JSON file."""
    with open(filepath, 'r') as f:
        return json.load(f)


def _make_serializable(obj):
    """Convert non-serializable types (bytes, etc.) to JSON-friendly format."""
    if isinstance(obj, bytes):
        return obj.hex()
    elif isinstance(obj, dict):
        return {k: _make_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [_make_serializable(item) for item in obj]
    return obj


# ─── Ticket Helpers ──────────────────────────────────────────────────────────

def create_ticket_payload(client_id, service_id, session_key, lifetime=300, key_version=1):
    """
    Create ticket payload as a JSON-serializable dict.
    """
    return {
        "client_id": client_id,
        "service_id": service_id,
        "timestamp": time.time(),
        "lifetime": lifetime,
        "session_key": session_key.hex() if isinstance(session_key, bytes) else session_key,
        "key_version": key_version
    }


def serialize_ticket(ticket_payload, signatures):
    """
    Serialize a ticket with its payload and signatures into JSON bytes.

    Args:
        ticket_payload: dict — ticket fields
        signatures: list of (R, s, authority_id) tuples

    Returns:
        bytes — JSON-encoded ticket
    """
    ticket = {
        "payload": ticket_payload,
        "signatures": [
            {"R": str(R), "s": str(s), "authority_id": auth_id}
            for R, s, auth_id in signatures
        ]
    }
    return json.dumps(ticket).encode('utf-8')


def deserialize_ticket(ticket_bytes):
    """
    Deserialize a ticket from JSON bytes.

    Returns:
        (payload_dict, signatures list of (R, s, authority_id))
    """
    if isinstance(ticket_bytes, bytes):
        ticket_bytes = ticket_bytes.decode('utf-8')
    ticket = json.loads(ticket_bytes)
    payload = ticket["payload"]
    signatures = [
        (int(sig["R"]), int(sig["s"]), sig["authority_id"])
        for sig in ticket["signatures"]
    ]
    return payload, signatures


def is_ticket_expired(ticket_payload):
    """Check if a ticket has expired based on timestamp + lifetime."""
    issued = ticket_payload["timestamp"]
    lifetime = ticket_payload["lifetime"]
    return time.time() > (issued + lifetime)


# ─── Network Message Protocol ────────────────────────────────────────────────

def send_message(sock, data):
    """Send a length-prefixed JSON message over a socket."""
    if isinstance(data, dict) or isinstance(data, list):
        raw = json.dumps(data, default=str).encode('utf-8')
    elif isinstance(data, str):
        raw = data.encode('utf-8')
    elif isinstance(data, bytes):
        raw = data
    else:
        raw = json.dumps(data, default=str).encode('utf-8')

    length = struct.pack('!I', len(raw))
    sock.sendall(length + raw)


def recv_message(sock):
    """Receive a length-prefixed JSON message from a socket."""
    raw_len = _recv_exactly(sock, 4)
    if not raw_len:
        return None
    msg_len = struct.unpack('!I', raw_len)[0]
    raw_data = _recv_exactly(sock, msg_len)
    if not raw_data:
        return None
    return json.loads(raw_data.decode('utf-8'))


def _recv_exactly(sock, n):
    """Receive exactly n bytes from socket."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


# ─── User Database (simple in-memory) ────────────────────────────────────────

# Hardcoded user database for the demo
USER_DB = {
    "alice": hashlib.sha256("password_alice".encode()).hexdigest(),
    "bob": hashlib.sha256("password_bob".encode()).hexdigest(),
    "charlie": hashlib.sha256("password_charlie".encode()).hexdigest(),
}

def verify_user(username, password_hash):
    """Verify a user's credentials against the database."""
    return USER_DB.get(username) == password_hash
