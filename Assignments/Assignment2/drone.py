#!/usr/bin/env python3
"""
drone.py  –  Drone (UAV) Client

Implements the client-side of the secure UAV C2 protocol:
  Phase 0 – Receive & validate parameters from MCC
  Phase 1A – Send authentication request
  Phase 1B – Receive & verify MCC response
  Phase 2 – Session key confirmation
  Phase 3 – Receive Group Key and broadcast commands
"""

import socket
import json
import time
import sys
import threading
import secrets

from crypto_utils import (
    elgamal_keygen, elgamal_encrypt, elgamal_decrypt,
    elgamal_sign, elgamal_verify,
    mod_exp, int_to_bytes, bytes_to_int,
    sha256, compute_hmac, verify_hmac,
    aes_cbc_encrypt, aes_cbc_decrypt,
    derive_session_key,
    pack_message, recv_message,
)

# ──────────────────────────────  OPCODES  ────────────────────────────────────

OP_PARAM_INIT   = 10
OP_AUTH_REQ      = 20
OP_AUTH_RES      = 30
OP_SK_CONFIRM    = 40
OP_SUCCESS       = 50
OP_ERR_MISMATCH  = 60
OP_GROUP_KEY     = 70
OP_GROUP_CMD     = 80
OP_SHUTDOWN      = 90

# ────────────────────────────  COLOURS  ──────────────────────────────────────

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"

# ────────────────────────────  CONSTANTS  ────────────────────────────────────

MIN_SECURITY_LEVEL = 2048           # hardcoded safety limit
TS_FRESHNESS       = 30             # max seconds for timestamp freshness


# ──────────────────────────  Drone Client  ───────────────────────────────────

class Drone:

    def __init__(self, drone_id: str, mcc_host: str = "127.0.0.1", mcc_port: int = 9999):
        self.drone_id = drone_id
        self.mcc_host = mcc_host
        self.mcc_port = mcc_port
        self.sock: socket.socket | None = None
        self.session_key: bytes | None = None
        self.group_key: bytes | None = None

        # Crypto state (populated during Phase 0)
        self.p: int | None = None
        self.g: int | None = None
        self.x_drone: int | None = None       # private key
        self.y_drone: int | None = None       # public key
        self.y_mcc: int | None = None         # MCC's public key

    # ────────────────────  Connect & Run  ────────────────────────────────────

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.mcc_host, self.mcc_port))
        print(f"{GREEN}[{self.drone_id}] Connected to MCC at {self.mcc_host}:{self.mcc_port}{RESET}")

        try:
            self._phase0()
            self._phase1()
            self._phase2()
            self._phase3_listen()
        except (ConnectionError, ValueError, json.JSONDecodeError) as e:
            print(f"{RED}[{self.drone_id}] Error: {e}{RESET}")
        finally:
            if self.sock:
                try:
                    self.sock.close()
                except Exception:
                    pass
            print(f"{YELLOW}[{self.drone_id}] Disconnected.{RESET}")

    # ─────────────────  Phase 0: Parameter Initialization  ───────────────────

    def _phase0(self):
        opcode, payload = recv_message(self.sock)
        if opcode != OP_PARAM_INIT:
            raise ValueError(f"Expected PARAM_INIT (10), got {opcode}")

        outer = json.loads(payload)
        m0_data_str = outer["data"]
        sig_r = int(outer["sig_r"])
        sig_s = int(outer["sig_s"])

        params = json.loads(m0_data_str)
        p       = int(params["p"])
        g       = int(params["g"])
        SL      = int(params["SL"])
        ts0     = params["TS0"]
        id_mcc  = params["ID_MCC"]
        y_mcc   = int(params["y_mcc"])

        # ── Validation ──────────────────────────────────────────────────

        # 1. Check SL meets minimum
        if SL < MIN_SECURITY_LEVEL:
            raise ValueError(f"SL={SL} below minimum {MIN_SECURITY_LEVEL}")

        # 2. Check p bit-length ≈ SL
        p_bits = p.bit_length()
        if p_bits < SL:
            raise ValueError(f"Inconsistent: SL={SL} but p has only {p_bits} bits")

        # 3. Timestamp freshness
        if abs(time.time() - float(ts0)) > TS_FRESHNESS:
            raise ValueError("Phase 0 timestamp is stale")

        # 4. Verify MCC signature on m0_data
        if not elgamal_verify(m0_data_str.encode(), sig_r, sig_s, y_mcc, p, g):
            raise ValueError("Phase 0 MCC signature verification FAILED")

        self.p = p
        self.g = g
        self.y_mcc = y_mcc

        # Generate drone key pair with received parameters
        self.x_drone, self.y_drone = elgamal_keygen(p, g)

        print(f"{GREEN}[{self.drone_id}] Phase 0 ✓  SL={SL}, p bits={p_bits}{RESET}")

    # ─────────────────  Phase 1: Mutual Authentication  ──────────────────────

    def _phase1(self):
        # ── Phase 1A: Send AUTH_REQ ──────────────────────────────────────
        # Generate random shared secret K ∈ [1, p-2] and nonce RN
        K_raw = secrets.randbelow(self.p - 2) + 1          # K in [1, p-2]
        K_bytes = int_to_bytes(K_raw)
        rn_i = secrets.token_hex(256)                        # 2048-bit nonce
        ts_i = str(time.time())

        # Encrypt K under MCC public key
        c1, c2 = elgamal_encrypt(K_raw, self.p, self.g, self.y_mcc)

        # Sign (TS_i || RN_i || ID_Di || C_i)
        sig_data = (ts_i + rn_i + self.drone_id + str(c1) + str(c2)).encode()
        sig_r, sig_s = elgamal_sign(sig_data, self.x_drone, self.p, self.g)

        req = json.dumps({
            "TS_i":   ts_i,
            "RN_i":   rn_i,
            "ID_Di":  self.drone_id,
            "C1":     str(c1),
            "C2":     str(c2),
            "sig_r":  str(sig_r),
            "sig_s":  str(sig_s),
            "y_drone": str(self.y_drone),
        }).encode()
        self.sock.sendall(pack_message(OP_AUTH_REQ, req))
        print(f"{GREEN}[{self.drone_id}] Phase 1A → sent AUTH_REQ{RESET}")

        # ── Phase 1B: Receive AUTH_RES ───────────────────────────────────
        opcode, payload = recv_message(self.sock)
        if opcode == OP_ERR_MISMATCH:
            raise ValueError(f"MCC rejected authentication: {payload.decode()}")
        if opcode != OP_AUTH_RES:
            raise ValueError(f"Expected AUTH_RES (30), got {opcode}")

        res = json.loads(payload)
        ts_mcc  = res["TS_MCC"]
        rn_mcc  = res["RN_MCC"]
        id_mcc  = res["ID_MCC"]
        c1_mcc  = int(res["C1"])
        c2_mcc  = int(res["C2"])
        sig_r_m = int(res["sig_r"])
        sig_s_m = int(res["sig_s"])

        # Verify MCC signature
        sig_data_mcc = (ts_mcc + rn_mcc + id_mcc + str(c1_mcc) + str(c2_mcc)).encode()
        if not elgamal_verify(sig_data_mcc, sig_r_m, sig_s_m, self.y_mcc, self.p, self.g):
            raise ValueError("Phase 1B: MCC signature verification FAILED")

        # Decrypt K back – should match what we sent
        K_decrypted = elgamal_decrypt(c1_mcc, c2_mcc, self.x_drone, self.p)
        if K_decrypted != K_raw:
            raise ValueError("Phase 1B: Decrypted key does not match sent key – possible MitM!")

        print(f"{GREEN}[{self.drone_id}] Phase 1B ✓  MCC signature verified, key confirmed{RESET}")

        # Save for Phase 2
        self.ts_i   = ts_i
        self.ts_mcc = ts_mcc
        self.rn_i   = rn_i
        self.rn_mcc = rn_mcc
        # Both sides use int_to_bytes(K_raw) as the key material for SK derivation
        self.K_bytes_raw = int_to_bytes(K_raw)

    # ─────────────────  Phase 2: Session Key Confirmation  ───────────────────

    def _phase2(self):
        # Derive session key: SK = SHA-256( K || TS_i || TS_MCC || RN_i || RN_MCC )
        sk = derive_session_key(self.K_bytes_raw, self.ts_i, self.ts_mcc,
                                self.rn_i, self.rn_mcc)
        self.session_key = sk
        print(f"{GREEN}[{self.drone_id}] Session key derived (first 8B): {sk[:8].hex()}{RESET}")

        # Send HMAC_SK( ID_Di || TS_final )
        ts_final = str(time.time())
        hmac_data = (self.drone_id + ts_final).encode()
        hmac_val = compute_hmac(sk, hmac_data)

        confirm = json.dumps({
            "hmac": hmac_val.hex(),
            "TS_final": ts_final,
        }).encode()
        self.sock.sendall(pack_message(OP_SK_CONFIRM, confirm))
        print(f"{GREEN}[{self.drone_id}] Phase 2 → sent SK_CONFIRM{RESET}")

        # Receive response
        opcode, payload = recv_message(self.sock)
        if opcode == OP_SUCCESS:
            print(f"{GREEN}[{self.drone_id}] Phase 2 ✓  Handshake COMPLETE ✓{RESET}")
        elif opcode == OP_ERR_MISMATCH:
            raise ValueError(f"Phase 2: MCC reported MISMATCH – {payload.decode()}")
        else:
            raise ValueError(f"Phase 2: Unexpected opcode {opcode}")

    # ─────────────────  Phase 3: Group Key & Broadcast  ──────────────────────

    def _phase3_listen(self):
        """Listen for Group Key distribution and broadcast commands."""
        print(f"{CYAN}[{self.drone_id}] Listening for Phase 3 commands …{RESET}")
        self.sock.settimeout(2.0)

        while True:
            try:
                opcode, payload = recv_message(self.sock)
            except socket.timeout:
                continue
            except (ConnectionError, ValueError):
                print(f"{YELLOW}[{self.drone_id}] Connection closed.{RESET}")
                break

            if opcode == OP_GROUP_KEY:
                self._handle_group_key(payload)
            elif opcode == OP_GROUP_CMD:
                self._handle_group_cmd(payload)
            elif opcode == OP_SHUTDOWN:
                print(f"{YELLOW}[{self.drone_id}] Received SHUTDOWN from MCC.{RESET}")
                break
            else:
                print(f"{YELLOW}[{self.drone_id}] Unknown opcode {opcode}{RESET}")

    def _handle_group_key(self, payload: bytes):
        """Decrypt group key sent by MCC (encrypted with our session key)."""
        try:
            parts = payload.split(b"||", 1)
            meta = json.loads(parts[0])
            enc_gk = parts[1]
            gk = aes_cbc_decrypt(self.session_key, enc_gk)
            self.group_key = gk
            print(f"{GREEN}[{self.drone_id}] Group Key received (first 8B): {gk[:8].hex()}{RESET}")
        except Exception as e:
            print(f"{RED}[{self.drone_id}] Failed to decrypt Group Key: {e}{RESET}")

    def _handle_group_cmd(self, payload: bytes):
        """Decrypt and verify broadcast command (encrypted with group key)."""
        try:
            parts = payload.split(b"||")
            enc_cmd = parts[0]
            hmac_val = parts[1]

            if self.group_key is None:
                print(f"{RED}[{self.drone_id}] No group key – cannot decrypt command{RESET}")
                return

            cmd = aes_cbc_decrypt(self.group_key, enc_cmd)

            # Verify HMAC
            if verify_hmac(self.group_key, cmd, hmac_val):
                print(f"{GREEN}[{self.drone_id}] ✓ Broadcast command: {cmd.decode()}{RESET}")
            else:
                print(f"{RED}[{self.drone_id}] ✗ HMAC verification failed for broadcast{RESET}")
        except Exception as e:
            print(f"{RED}[{self.drone_id}] Failed to process broadcast: {e}{RESET}")


# ─────────────────────────────  Entry Point  ─────────────────────────────────

def main():
    drone_id = sys.argv[1] if len(sys.argv) > 1 else "DRONE-1"
    host     = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    port     = int(sys.argv[3]) if len(sys.argv) > 3 else 9999

    drone = Drone(drone_id, host, port)
    drone.connect()


if __name__ == "__main__":
    main()
