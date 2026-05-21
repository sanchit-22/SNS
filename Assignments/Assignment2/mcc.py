#!/usr/bin/env python3
"""
mcc.py  –  Mission Control Center (MCC) Server

Multi-threaded server implementing the secure UAV C2 protocol:
  Phase 0 – Parameter Initialization
  Phase 1 – Mutual Authentication (1A receive, 1B respond)
  Phase 2 – Session Key Confirmation
  Phase 3 – Group Key Establishment & Broadcast

CLI commands:  list  |  broadcast <cmd>  |  shutdown
"""

import socket
import threading
import json
import time
import sys
import secrets
import os

from crypto_utils import (
    get_safe_prime_and_generator,
    elgamal_keygen, elgamal_encrypt, elgamal_decrypt,
    elgamal_sign, elgamal_verify,
    mod_exp, int_to_bytes, bytes_to_int,
    sha256, sha256_hex, compute_hmac, verify_hmac,
    aes_cbc_encrypt, aes_cbc_decrypt,
    derive_session_key, derive_group_key,
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

# ──────────────────────────  Fleet Registry  ─────────────────────────────────

class FleetRegistry:
    """Thread-safe registry of authenticated drones."""

    def __init__(self):
        self.lock = threading.Lock()
        self.drones: dict = {}          # drone_id → DroneEntry
        self.blocked: set = set()       # blocked drone IDs

    def register(self, drone_id: str, sock, session_key: bytes, pub_key: int):
        with self.lock:
            self.drones[drone_id] = {
                "sock": sock,
                "session_key": session_key,
                "pub_key": pub_key,
                "connected_at": time.strftime("%H:%M:%S"),
            }

    def remove(self, drone_id: str):
        with self.lock:
            self.drones.pop(drone_id, None)

    def block(self, drone_id: str):
        with self.lock:
            self.blocked.add(drone_id)

    def is_blocked(self, drone_id: str) -> bool:
        with self.lock:
            return drone_id in self.blocked

    def get_all(self) -> dict:
        with self.lock:
            return dict(self.drones)

    def get(self, drone_id: str):
        with self.lock:
            return self.drones.get(drone_id)


# ──────────────────────────  MCC Server  ─────────────────────────────────────

class MCCServer:

    HOST = "127.0.0.1"
    PORT = 9999
    SL   = 2048                      # security level in bits
    MCC_ID = "MCC-ALPHA"

    def __init__(self):
        self.fleet = FleetRegistry()
        self.running = threading.Event()
        self.running.set()

        # ── Generate crypto parameters ──────────────────────────────────
        print(f"{CYAN}[MCC] Loading {self.SL}-bit safe prime …{RESET}")
        t0 = time.perf_counter()
        self.p, self.g = get_safe_prime_and_generator(self.SL)
        elapsed = time.perf_counter() - t0
        print(f"{GREEN}[MCC] Prime ready in {elapsed:.4f}s  (p bit-length={self.p.bit_length()}, g={self.g}){RESET}")

        # MCC key pair
        self.x_mcc, self.y_mcc = elgamal_keygen(self.p, self.g)
        print(f"{GREEN}[MCC] ElGamal key pair generated.{RESET}")

        # Known drone public keys  (populated when drones register in Phase 0/1)
        # In a real system these would be pre-shared; here drones send pub keys in AUTH_REQ.
        self.drone_pub_keys: dict = {}     # drone_id → y_drone

        # TCP socket
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.settimeout(1.0)

    # ─────────────────  start / stop  ────────────────────────────────────────

    def start(self):
        self.server_sock.bind((self.HOST, self.PORT))
        self.server_sock.listen(10)
        print(f"{GREEN}[MCC] Listening on {self.HOST}:{self.PORT}{RESET}")

        accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        accept_thread.start()

        self._cli_loop()

    def _accept_loop(self):
        while self.running.is_set():
            try:
                conn, addr = self.server_sock.accept()
                print(f"\n{CYAN}[MCC] Incoming connection from {addr}{RESET}")
                t = threading.Thread(target=self._handle_drone, args=(conn, addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break

    # ─────────────────  CLI loop  ────────────────────────────────────────────

    def _cli_loop(self):
        print(f"{YELLOW}[MCC] CLI ready.  Commands: list | broadcast <cmd> | shutdown{RESET}")
        while self.running.is_set():
            try:
                cmd = input(f"{YELLOW}MCC> {RESET}").strip()
            except (EOFError, KeyboardInterrupt):
                self._do_shutdown()
                break
            if not cmd:
                continue
            parts = cmd.split(None, 1)
            verb = parts[0].lower()

            if verb == "list":
                self._do_list()
            elif verb == "broadcast":
                if len(parts) < 2:
                    print(f"{RED}Usage: broadcast <command>{RESET}")
                else:
                    self._do_broadcast(parts[1])
            elif verb == "shutdown":
                self._do_shutdown()
                break
            else:
                print(f"{RED}Unknown command: {verb}{RESET}")

    # ─────────────  CLI: list  ───────────────────────────────────────────────

    def _do_list(self):
        drones = self.fleet.get_all()
        if not drones:
            print(f"{YELLOW}  (no authenticated drones){RESET}")
            return
        print(f"{CYAN}  {'Drone ID':<20} {'Connected At':<15} {'SK (hex, first 8B)':<20}{RESET}")
        for did, info in drones.items():
            sk_hex = info["session_key"][:8].hex()
            print(f"  {did:<20} {info['connected_at']:<15} {sk_hex}…")

    # ─────────────  CLI: broadcast  ──────────────────────────────────────────

    def _do_broadcast(self, command: str):
        drones = self.fleet.get_all()
        if not drones:
            print(f"{RED}[MCC] No drones connected.{RESET}")
            return

        # Phase 3 – generate group key
        sk_list = sorted(drones.keys())
        session_keys = [drones[d]["session_key"] for d in sk_list]
        mcc_priv_bytes = int_to_bytes(self.x_mcc)
        gk = derive_group_key(session_keys, mcc_priv_bytes)
        print(f"{GREEN}[MCC] Group Key derived (first 8B): {gk[:8].hex()}{RESET}")

        # Distribute GK to each drone encrypted with their SK (AES-256-CBC)
        for did in sk_list:
            info = drones[did]
            try:
                enc_gk = aes_cbc_encrypt(info["session_key"], gk)
                payload = json.dumps({"drone_id": did}).encode() + b"||" + enc_gk
                info["sock"].sendall(pack_message(OP_GROUP_KEY, payload))
                print(f"{GREEN}  → Sent GK to {did}{RESET}")
            except Exception as e:
                print(f"{RED}  ✗ Failed sending GK to {did}: {e}{RESET}")
                self.fleet.remove(did)

        # Broadcast the command encrypted with GK
        for did in sk_list:
            info = drones.get(did) or self.fleet.get(did)
            if info is None:
                continue
            try:
                enc_cmd = aes_cbc_encrypt(gk, command.encode())
                hmac_val = compute_hmac(gk, command.encode())
                payload = enc_cmd + b"||" + hmac_val
                info["sock"].sendall(pack_message(OP_GROUP_CMD, payload))
                print(f"{GREEN}  → Broadcast to {did}: {command}{RESET}")
            except Exception as e:
                print(f"{RED}  ✗ Failed broadcast to {did}: {e}{RESET}")
                self.fleet.remove(did)

    # ─────────────  CLI: shutdown  ───────────────────────────────────────────

    def _do_shutdown(self):
        print(f"{YELLOW}[MCC] Shutting down …{RESET}")
        self.running.clear()
        drones = self.fleet.get_all()
        for did, info in drones.items():
            try:
                info["sock"].sendall(pack_message(OP_SHUTDOWN, b""))
            except Exception:
                pass
            try:
                info["sock"].close()
            except Exception:
                pass
            self.fleet.remove(did)
        try:
            self.server_sock.close()
        except Exception:
            pass
        print(f"{GREEN}[MCC] Shutdown complete.{RESET}")

    # ─────────────  Per-drone handler (Phases 0-2)  ──────────────────────────

    def _handle_drone(self, conn: socket.socket, addr):
        drone_id = None
        try:
            # ── Phase 0: Send parameters ────────────────────────────────
            ts0 = str(time.time())
            m0_data = json.dumps({
                "p": str(self.p),
                "g": str(self.g),
                "SL": self.SL,
                "TS0": ts0,
                "ID_MCC": self.MCC_ID,
                "y_mcc": str(self.y_mcc),                 # MCC public key
            }).encode()
            sig_r, sig_s = elgamal_sign(m0_data, self.x_mcc, self.p, self.g)
            phase0_payload = json.dumps({
                "data": m0_data.decode(),
                "sig_r": str(sig_r),
                "sig_s": str(sig_s),
            }).encode()
            conn.sendall(pack_message(OP_PARAM_INIT, phase0_payload))
            print(f"{GREEN}[MCC] Phase 0 → sent to {addr}{RESET}")

            # ── Phase 1A: Receive AUTH_REQ from Drone ────────────────────
            opcode, payload = recv_message(conn)
            if opcode != OP_AUTH_REQ:
                print(f"{RED}[MCC] Expected AUTH_REQ (20), got {opcode}{RESET}")
                conn.close()
                return

            req = json.loads(payload)
            drone_id   = req["ID_Di"]
            ts_i       = req["TS_i"]
            rn_i       = req["RN_i"]
            c1_drone   = int(req["C1"])
            c2_drone   = int(req["C2"])
            sig_r_d    = int(req["sig_r"])
            sig_s_d    = int(req["sig_s"])
            y_drone    = int(req["y_drone"])               # drone's public key

            print(f"{CYAN}[MCC] Phase 1A ← from {drone_id}{RESET}")

            # Check if blocked
            if self.fleet.is_blocked(drone_id):
                print(f"{RED}[MCC] Drone {drone_id} is BLOCKED.{RESET}")
                conn.sendall(pack_message(OP_ERR_MISMATCH, b"BLOCKED"))
                conn.close()
                return

            # Timestamp freshness check (within 30 seconds)
            if abs(time.time() - float(ts_i)) > 30:
                print(f"{RED}[MCC] Stale timestamp from {drone_id}{RESET}")
                conn.sendall(pack_message(OP_ERR_MISMATCH, b"STALE_TS"))
                conn.close()
                return

            # Verify drone signature
            sig_data = (ts_i + rn_i + drone_id + str(c1_drone) + str(c2_drone)).encode()
            if not elgamal_verify(sig_data, sig_r_d, sig_s_d, y_drone, self.p, self.g):
                print(f"{RED}[MCC] Signature verification FAILED for {drone_id}{RESET}")
                conn.sendall(pack_message(OP_ERR_MISMATCH, b"BAD_SIG"))
                conn.close()
                return
            print(f"{GREEN}[MCC] Drone {drone_id} signature verified.{RESET}")

            # Store drone's public key
            self.drone_pub_keys[drone_id] = y_drone

            # Decrypt K_{Di,MCC}
            K_raw = elgamal_decrypt(c1_drone, c2_drone, self.x_mcc, self.p)
            K_bytes = int_to_bytes(K_raw)
            print(f"{GREEN}[MCC] Decrypted shared secret K (first 8B): {K_bytes[:8].hex()}{RESET}")

            # ── Phase 1B: Send AUTH_RES ──────────────────────────────────
            ts_mcc = str(time.time())
            rn_mcc = secrets.token_hex(256)                 # 2048-bit nonce

            # Encrypt the same key back to drone with drone's public key
            c1_mcc, c2_mcc = elgamal_encrypt(K_raw, self.p, self.g, y_drone)

            sig_data_mcc = (ts_mcc + rn_mcc + self.MCC_ID + str(c1_mcc) + str(c2_mcc)).encode()
            sig_r_m, sig_s_m = elgamal_sign(sig_data_mcc, self.x_mcc, self.p, self.g)

            res = json.dumps({
                "TS_MCC": ts_mcc,
                "RN_MCC": rn_mcc,
                "ID_MCC": self.MCC_ID,
                "C1": str(c1_mcc),
                "C2": str(c2_mcc),
                "sig_r": str(sig_r_m),
                "sig_s": str(sig_s_m),
            }).encode()
            conn.sendall(pack_message(OP_AUTH_RES, res))
            print(f"{GREEN}[MCC] Phase 1B → sent to {drone_id}{RESET}")

            # ── Phase 2: Session Key Confirmation ────────────────────────
            sk = derive_session_key(K_bytes, ts_i, ts_mcc, rn_i, rn_mcc)
            print(f"{GREEN}[MCC] Session key derived (first 8B): {sk[:8].hex()}{RESET}")

            opcode2, payload2 = recv_message(conn)
            if opcode2 != OP_SK_CONFIRM:
                print(f"{RED}[MCC] Expected SK_CONFIRM (40), got {opcode2}{RESET}")
                conn.close()
                return

            # Drone sends HMAC_SK( ID_Di || TS_final )
            confirm_data = json.loads(payload2)
            drone_hmac = bytes.fromhex(confirm_data["hmac"])
            ts_final   = confirm_data["TS_final"]
            expected_data = (drone_id + ts_final).encode()

            if verify_hmac(sk, expected_data, drone_hmac):
                print(f"{GREEN}[MCC] HMAC verified for {drone_id} – handshake COMPLETE ✓{RESET}")
                conn.sendall(pack_message(OP_SUCCESS, json.dumps({"status": "CONFIRMED"}).encode()))
                self.fleet.register(drone_id, conn, sk, y_drone)
            else:
                print(f"{RED}[MCC] HMAC mismatch for {drone_id} – blocking!{RESET}")
                conn.sendall(pack_message(OP_ERR_MISMATCH, json.dumps({"status": "MISMATCH"}).encode()))
                self.fleet.block(drone_id)
                conn.close()
                return

            # ── Keep connection alive for Phase 3 commands ───────────────
            # The drone thread stays alive; group key / broadcast are
            # pushed from the CLI via _do_broadcast().  We just wait here
            # so the thread (and the socket) remain open.
            while self.running.is_set():
                conn.settimeout(2.0)
                try:
                    opcode3, _ = recv_message(conn)
                    if opcode3 == OP_SHUTDOWN:
                        break
                except socket.timeout:
                    continue
                except (ConnectionError, ValueError, OSError):
                    break

        except (ConnectionError, ValueError, json.JSONDecodeError) as e:
            print(f"{RED}[MCC] Error handling drone {drone_id or addr}: {e}{RESET}")
        finally:
            if drone_id:
                self.fleet.remove(drone_id)
                print(f"{YELLOW}[MCC] Drone {drone_id} disconnected.{RESET}")
            try:
                conn.close()
            except Exception:
                pass


# ─────────────────────────────  Entry Point  ─────────────────────────────────

if __name__ == "__main__":
    server = MCCServer()
    server.start()
