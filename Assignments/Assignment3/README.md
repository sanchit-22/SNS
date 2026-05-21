# Kerberos Under Partial Compromise using Schnorr Multi-Signatures

A Kerberos-inspired authentication system resilient to partial authority compromise, using a **2-of-3 Schnorr multi-signature** scheme.

## Architecture

```
┌──────────────┐     ┌──────────────────────────────────────┐
│              │◄───►│  AS Cluster (Authentication Servers)  │
│              │     │  ┌──────┐ ┌──────┐ ┌──────┐          │
│              │     │  │ AS1  │ │ AS2  │ │ AS3  │          │
│              │     │  │:5001 │ │:5002 │ │:5003 │          │
│              │     │  └──────┘ └──────┘ └──────┘          │
│              │     └──────────────────────────────────────┘
│              │
│    Client    │     ┌──────────────────────────────────────┐
│              │◄───►│ TGS Cluster (Ticket Granting Servers) │
│              │     │  ┌──────┐ ┌──────┐ ┌──────┐          │
│              │     │  │ TGS1 │ │ TGS2 │ │ TGS3 │          │
│              │     │  │:6001 │ │:6002 │ │:6003 │          │
│              │     │  └──────┘ └──────┘ └──────┘          │
│              │     └──────────────────────────────────────┘
│              │
│              │     ┌──────────────────────────────────────┐
│              │◄───►│         Service Server                │
│              │     │         SERVICE1 :7001                 │
└──────────────┘     └──────────────────────────────────────┘
```

Each authority has an **independent** Schnorr key pair. A ticket is valid **only** if at least **2 out of 3** authorities have signed it.

## Prerequisites

- Python 3.8+
- Virtual environment `myenv`

## Setup & Running

### 1. Activate virtual environment
```bash
source myenv/bin/activate
```

### 2. Install dependencies
```bash
pip install cryptography
```

### 3. Generate keys
```bash
python3 master_keygen.py
```
This generates Schnorr parameters (p, q, g) and independent key pairs for all 6 authorities, stored in `config/`.

### 4. Start all servers (in separate terminals)

**Terminal 1 — AS Cluster:**
```bash
python3 as_node.py
```

**Terminal 2 — TGS Cluster:**
```bash
python3 tgs_node.py
```

**Terminal 3 — Service Server:**
```bash
python3 service_server.py
```

### 5. Run client
```bash
python3 client.py
```
The client performs the full 3-phase Kerberos flow:
1. **Phase 1**: Contacts AS1, AS2, AS3 → collects ≥2 TGT signatures
2. **Phase 2**: Contacts TGS1, TGS2, TGS3 → collects ≥2 service ticket signatures
3. **Phase 3**: Presents service ticket to SERVICE1 → access granted/denied

### 6. Run attack scenarios
```bash
python3 attacks.py
```
Demonstrates 6 attack scenarios with colorful pass/fail output.

## File Structure

| File | Description |
|------|-------------|
| `crypto_utils.py` | Schnorr signatures, AES-256-CBC, PKCS#7, modular arithmetic |
| `master_keygen.py` | Generate Schnorr parameters and key pairs for all authorities |
| `as_node.py` | 3 independent Authentication Servers on ports 5001-5003 |
| `tgs_node.py` | 3 independent Ticket Granting Servers on ports 6001-6003 |
| `service_server.py` | Service server that verifies ≥2 TGS signatures |
| `client.py` | Client implementing 3-phase Kerberos authentication |
| `attacks.py` | 6 mandatory attack scenario demonstrations |
| `config/` | Generated keys and configuration |

## Attack Scenarios

1. **Single Malicious Authority** — One compromised AS signs alone → rejected
2. **Modified Ticket Payload** — Tampered ticket → signature verification fails
3. **Replay Old Signature** — Reused (R,s) on new ticket → challenge mismatch
4. **Leaked Private Key** — One leaked key → still only 1 valid sig
5. **Authority Offline** — One AS down → system continues with remaining 2
6. **One Valid Signature** — 1 real + 1 fake sig → rejected

## Cryptographic Primitives

| Component | Implementation |
|-----------|---------------|
| Public Key Signature | Schnorr Multi-Signature (2-of-3) |
| Hash Function | SHA-256 |
| Symmetric Encryption | AES-256-CBC |
| Padding | Manual PKCS#7 |
| Randomness | OS-level secure RNG (`secrets`) |
| Modular Exponentiation | Manual square-and-multiply |

## Demo Users

| Username | Password |
|----------|----------|
| alice | password_alice |
| bob | password_bob |
| charlie | password_charlie |
