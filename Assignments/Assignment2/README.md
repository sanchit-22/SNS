# README.md — Secure UAV Command and Control System

## Overview

Implementation of a secure UAV Command-and-Control (C2) system for **CS8.403 System and Network Security — Lab Assignment 2**.

The system consists of:

- **MCC (Mission Control Center)** — Multi-threaded server (`mcc.py`)
- **Drones** — Client-side protocol logic (`drone.py`)
- **Crypto Utilities** — Manual ElGamal, modular math, AES/HMAC wrappers (`crypto_utils.py`)
- **Attack Demos** — Replay, MitM tamper, unauthorized access (`attacks.py`)

## Files

| File              | Description                                                                                                                                       |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `crypto_utils.py` | Manual ElGamal (keygen, encrypt, decrypt, sign, verify), modular exponentiation, modular inverse, safe-prime generation, AES-256-CBC, HMAC-SHA256 |
| `mcc.py`          | MCC server — TCP listener, per-drone threads, fleet registry, CLI (`list`, `broadcast`, `shutdown`)                                               |
| `drone.py`        | Drone client — Phase 0 validation, Phase 1 mutual auth, Phase 2 session key, Phase 3 group key                                                    |
| `attacks.py`      | Attack demonstrations: replay, MitM tampering, unauthorized access                                                                                |
| `SECURITY.md`     | Security analysis — freshness & forward secrecy                                                                                                   |
| `README.md`       | This file                                                                                                                                         |

## Requirements

- Python 3.10+
- `pycryptodome` (for AES-CBC block cipher only)

```bash
pip install pycryptodome
```

## How to Run

### 1. Start the MCC Server

```bash
python mcc.py
```

The MCC loads the RFC 3526 Group 14 2048-bit safe prime and finds a generator (~70ms), then listens on `127.0.0.1:9999`.

### 2. Connect Drones (separate terminals)

```bash
python drone.py DRONE-1
python drone.py DRONE-2
python drone.py DRONE-3
```

Each drone performs Phases 0–2 automatically and then listens for Phase 3 commands.

### 3. MCC CLI Commands

```
MCC> list               # Show authenticated drones
MCC> broadcast RTB      # Send encrypted command to fleet
MCC> shutdown           # Graceful shutdown
```

### 4. Run Attack Demos

```bash
python attacks.py replay         # Replay attack
python attacks.py mitm           # MitM parameter tampering
python attacks.py unauthorized   # Unknown drone ID
python attacks.py all            # Run all attacks
```

## Protocol Phases

1. **Phase 0** — MCC sends `(p, g, SL, TS, ID_MCC, y_MCC)` signed with ElGamal.
2. **Phase 1A** — Drone generates random K, encrypts under MCC's public key, signs and sends.
3. **Phase 1B** — MCC decrypts K, re-encrypts under drone's public key, signs and sends.
4. **Phase 2** — Both derive `SK = SHA-256(K || TS_i || TS_MCC || RN_i || RN_MCC)`. Drone sends HMAC confirmation.
5. **Phase 3** — MCC derives `GK = SHA-256(SK_1 || ... || SK_n || x_MCC)`, distributes GK via AES-CBC, broadcasts encrypted commands.

## Performance Logs

Benchmarks on the development machine (2048-bit parameters):

```
Operation                  Average Time
─────────────────────────  ────────────
Prime setup (RFC 3526)       70.37 ms
ElGamal keygen               35.37 ms
ElGamal sign                 36.32 ms
ElGamal verify               75.02 ms
ElGamal encrypt              70.34 ms
ElGamal decrypt              35.75 ms
Modular exponentiation       34.39 ms   (built-in pow)
Manual mod_exp (Python)      46.78 ms   (square-and-multiply)
AES-256-CBC encrypt 1KB       0.023 ms
AES-256-CBC decrypt 1KB       0.013 ms
HMAC-SHA256 1KB                0.004 ms
```

> The 2048-bit safe prime is loaded from RFC 3526 Group 14 (pre-computed) so there is no generation delay. A full generator for Z\*\_p is found at startup (~70ms). Actual times depend on hardware.

## Cryptographic Implementation

All asymmetric primitives are implemented manually:

- **Modular Exponentiation**: Square-and-multiply (right-to-left binary method) — `mod_exp_manual`
- **Modular Inverse**: Extended Euclidean Algorithm (iterative)
- **Primality Testing**: Miller-Rabin with 20+ rounds
- **Safe Prime**: RFC 3526 Group 14 pre-computed 2048-bit safe prime (`p = 2q+1`, both prime)
- **Generator Finding**: For safe prime `p = 2q+1`, check `g^2 ≠ 1` and `g^q ≠ 1 (mod p)` to find a full generator of Z\*\_p
- **ElGamal Encryption**: `c1 = g^k mod p`, `c2 = m · y^k mod p`
- **ElGamal Decryption**: `m = c2 · (c1^x)^{-1} mod p`
- **ElGamal Signing**: `r = g^k mod p`, `s = (H(m) - xr) · k^{-1} mod (p-1)`
- **ElGamal Verification**: `g^{H(m)} ≡ y^r · r^s (mod p)`

No high-level crypto libraries (OpenSSL, Crypto.PublicKey, etc.) are used for asymmetric operations.
