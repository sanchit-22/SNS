#!/usr/bin/env python3
"""
attacks.py  –  Demonstrate protocol attack scenarios

1. Replay Attack        – Re-send a captured Phase 1A AUTH_REQ message.
2. MitM Tampering       – Modify the prime p in Phase 0 to trigger signature failure.
3. Unauthorized Access  – An unknown Drone ID attempts to connect.

Usage:
    python attacks.py replay
    python attacks.py mitm
    python attacks.py unauthorized
    python attacks.py all            (run all three)
"""

import socket
import json
import time
import sys
import secrets

from crypto_utils import (
    elgamal_keygen, elgamal_encrypt, elgamal_decrypt,
    elgamal_sign, elgamal_verify,
    mod_exp, int_to_bytes, bytes_to_int,
    sha256, compute_hmac,
    pack_message, recv_message,
    derive_session_key,
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
BOLD   = "\033[1m"
RESET  = "\033[0m"

MCC_HOST = "127.0.0.1"
MCC_PORT = 9999


# ═══════════════════════════════════════════════════════════════════════════════
#  Attack 1: Replay Attack
# ═══════════════════════════════════════════════════════════════════════════════

def attack_replay():
    """
    Replay Attack – Third-party replaying a captured Phase 1A AUTH_REQ

    Strategy:
      1. Legitimate drone performs Phase 0 + Phase 1A.
         A third-party eavesdropper captures the raw AUTH_REQ bytes.
      2. The eavesdropper (attacker) opens a NEW connection to MCC.
      3. Attacker replays the *exact same* Phase 1A message.
      4. Even if MCC responds (within the timestamp window), the attacker
         does NOT know the drone's private key → cannot decrypt AUTH_RES →
         cannot derive session key → Phase 2 HMAC will FAIL.
      5. If replayed after >30s, MCC rejects outright due to stale timestamp.
    """
    print(f"\n{BOLD}{CYAN}{'='*70}")
    print("  ATTACK 1: REPLAY ATTACK  –  Third-party replays captured AUTH_REQ")
    print(f"{'='*70}{RESET}\n")

    # ── Step 1: Legitimate connection – capture Phase 1A ─────────────
    print(f"{YELLOW}[Step 1] Legitimate drone connects and sends Phase 1A …{RESET}")
    sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock1.connect((MCC_HOST, MCC_PORT))

    # Receive Phase 0
    opcode, payload = recv_message(sock1)
    assert opcode == OP_PARAM_INIT
    outer = json.loads(payload)
    params = json.loads(outer["data"])
    p = int(params["p"])
    g = int(params["g"])
    y_mcc = int(params["y_mcc"])

    # Generate drone keys (attacker does NOT have x_drone)
    x_drone, y_drone = elgamal_keygen(p, g)

    # Build Phase 1A
    K_raw = secrets.randbelow(p - 2) + 1
    rn_i = secrets.token_hex(256)
    ts_i = str(time.time())
    c1, c2 = elgamal_encrypt(K_raw, p, g, y_mcc)
    sig_data = (ts_i + rn_i + "DRONE-LEGIT" + str(c1) + str(c2)).encode()
    sig_r, sig_s = elgamal_sign(sig_data, x_drone, p, g)

    auth_req_payload = json.dumps({
        "TS_i": ts_i, "RN_i": rn_i, "ID_Di": "DRONE-LEGIT",
        "C1": str(c1), "C2": str(c2),
        "sig_r": str(sig_r), "sig_s": str(sig_s),
        "y_drone": str(y_drone),
    }).encode()

    captured_message = pack_message(OP_AUTH_REQ, auth_req_payload)
    sock1.sendall(captured_message)
    print(f"{GREEN}[Step 1] AUTH_REQ sent.  Eavesdropper captured raw bytes ({len(captured_message)} bytes).{RESET}")

    # Receive Phase 1B (legit response)
    opcode1b, _ = recv_message(sock1)
    print(f"{GREEN}[Step 1] Legitimate drone received AUTH_RES (opcode {opcode1b}).{RESET}")
    sock1.close()

    # ── Step 2: Attacker replays the captured message ────────────────
    print(f"\n{YELLOW}[Step 2] ATTACKER (third-party) replays captured AUTH_REQ …{RESET}")
    print(f"{YELLOW}  The attacker does NOT know K_raw or the drone's private key.{RESET}")

    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock2.connect((MCC_HOST, MCC_PORT))

    # Receive fresh Phase 0 (attacker ignores it)
    opcode0, _ = recv_message(sock2)
    assert opcode0 == OP_PARAM_INIT
    print(f"{YELLOW}[Step 2] Received fresh Phase 0 (attacker ignores it).{RESET}")

    # Replay the captured AUTH_REQ
    sock2.sendall(captured_message)
    print(f"{RED}[Step 2] REPLAYED the captured AUTH_REQ!{RESET}")

    try:
        sock2.settimeout(10)
        opcode_resp, payload_resp = recv_message(sock2)
        if opcode_resp == OP_ERR_MISMATCH:
            print(f"{GREEN}[RESULT] ✓ MCC REJECTED the replay! Reason: {payload_resp.decode()}{RESET}")
        elif opcode_resp == OP_AUTH_RES:
            print(f"{YELLOW}[Step 3] MCC sent AUTH_RES (timestamp still within 30s window).{RESET}")
            res = json.loads(payload_resp)
            ts_mcc = res["TS_MCC"]
            rn_mcc = res["RN_MCC"]

            # Attacker tries Phase 2 with a WRONG session key
            # (they don't know K_raw, so they use random bytes)
            print(f"{RED}[Step 3] Attacker cannot decrypt K from AUTH_RES (no private key).{RESET}")
            print(f"{RED}  Attempting Phase 2 with a RANDOM session key …{RESET}")

            fake_sk = secrets.token_bytes(32)
            ts_final = str(time.time())
            hmac_data = ("DRONE-LEGIT" + ts_final).encode()
            hmac_val = compute_hmac(fake_sk, hmac_data)
            confirm = json.dumps({"hmac": hmac_val.hex(), "TS_final": ts_final}).encode()
            sock2.sendall(pack_message(OP_SK_CONFIRM, confirm))

            opcode2, payload2 = recv_message(sock2)
            if opcode2 == OP_ERR_MISMATCH:
                print(f"{GREEN}[RESULT] ✓ MCC REJECTED at Phase 2! HMAC mismatch – drone blocked.{RESET}")
                print(f"{GREEN}  Reason: {payload2.decode()}{RESET}")
            elif opcode2 == OP_SUCCESS:
                print(f"{RED}[RESULT] ✗ MCC ACCEPTED (unexpected!){RESET}")
            else:
                print(f"{YELLOW}[RESULT] Unexpected opcode: {opcode2}{RESET}")
        else:
            print(f"{YELLOW}[RESULT] Unexpected opcode: {opcode_resp}{RESET}")
    except Exception as e:
        print(f"{GREEN}[RESULT] ✓ Connection error: {e}{RESET}")
    finally:
        sock2.close()

    print(f"\n{CYAN}Analysis: The replay attack is mitigated by multiple mechanisms:{RESET}")
    print(f"{CYAN}  1. Timestamp freshness (±30s) – after the window, MCC rejects outright.{RESET}")
    print(f"{CYAN}  2. Even within the window, the attacker cannot decrypt K from the{RESET}")
    print(f"{CYAN}     ciphertext (encrypted under MCC's public key) without MCC's private key.{RESET}")
    print(f"{CYAN}  3. The attacker cannot derive the session key without K.{RESET}")
    print(f"{CYAN}  4. Phase 2 HMAC verification fails → drone ID is blocked.{RESET}\n")


# ═══════════════════════════════════════════════════════════════════════════════
#  Attack 2: MitM Tampering  (Modify prime p in Phase 0)
# ═══════════════════════════════════════════════════════════════════════════════

def attack_mitm():
    """
    Man-in-the-Middle Tampering – Modify p in Phase 0

    Strategy:
      1. Connect to MCC, receive Phase 0 message.
      2. Tamper with the prime p (e.g., replace with a weak 512-bit prime).
      3. Try to verify the MCC's signature with the tampered data.
      4. Expected result: Signature verification FAILS because the data was modified.
    """
    print(f"\n{BOLD}{CYAN}{'='*70}")
    print("  ATTACK 2: MitM TAMPERING  –  Modify p in Phase 0")
    print(f"{'='*70}{RESET}\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((MCC_HOST, MCC_PORT))

    # Receive Phase 0
    opcode, payload = recv_message(sock)
    assert opcode == OP_PARAM_INIT
    outer = json.loads(payload)
    original_data = outer["data"]
    sig_r = int(outer["sig_r"])
    sig_s = int(outer["sig_s"])

    params = json.loads(original_data)
    p_original = int(params["p"])
    g_original = int(params["g"])
    y_mcc      = int(params["y_mcc"])

    print(f"{GREEN}[Step 1] Received Phase 0 from MCC.{RESET}")
    print(f"  Original p bit-length: {p_original.bit_length()}")

    # ── Step 2: Verify original signature (should pass) ──────────────
    ok = elgamal_verify(original_data.encode(), sig_r, sig_s, y_mcc, p_original, g_original)
    print(f"\n{GREEN}[Step 2] Original signature verification: {ok}  (should be True){RESET}")

    # ── Step 3: Tamper with p ────────────────────────────────────────
    print(f"\n{YELLOW}[Step 3] Tampering with p – replacing with a weak 512-bit prime …{RESET}")

    # Use a known small prime for tampering
    weak_p = 2**511 + 111          # not even prime, just to demonstrate
    params_tampered = dict(params)
    params_tampered["p"] = str(weak_p)
    tampered_data = json.dumps(params_tampered)

    print(f"  Tampered p bit-length: {weak_p.bit_length()}")

    # ── Step 4: Try to verify signature on tampered data ─────────────
    print(f"\n{RED}[Step 4] Verifying MCC signature on TAMPERED data …{RESET}")
    ok_tampered = elgamal_verify(tampered_data.encode(), sig_r, sig_s, y_mcc, p_original, g_original)
    print(f"  Signature verification on tampered data: {ok_tampered}")

    if not ok_tampered:
        print(f"\n{GREEN}[RESULT] ✓ SIGNATURE VERIFICATION FAILED on tampered data!{RESET}")
        print(f"{GREEN}  The MitM attack is detected – the drone would abort.{RESET}")
    else:
        print(f"\n{RED}[RESULT] ✗ Signature passed on tampered data (unexpected).{RESET}")

    # ── Step 5: Also check SL consistency ────────────────────────────
    print(f"\n{YELLOW}[Step 5] Checking SL consistency …{RESET}")
    claimed_SL = int(params["SL"])
    if weak_p.bit_length() < claimed_SL:
        print(f"{GREEN}  ✓ Drone detects inconsistency: claimed SL={claimed_SL} but p only {weak_p.bit_length()} bits.{RESET}")
    else:
        print(f"  p matches claimed SL.")

    sock.close()

    print(f"\n{CYAN}Analysis: The digital signature on Phase 0 parameters makes")
    print(f"any tampering with p, g, SL, or timestamp detectable. Additionally,")
    print(f"the drone independently checks that len(bin(p)) ≈ SL, preventing")
    print(f"a weak-prime downgrade attack.{RESET}\n")


# ═══════════════════════════════════════════════════════════════════════════════
#  Attack 3: Unauthorized Access  (Unknown Drone ID)
# ═══════════════════════════════════════════════════════════════════════════════

def attack_unauthorized():
    """
    Unauthorized Access – Unknown Drone ID

    Strategy:
      1. Connect to MCC with a fabricated/unknown drone ID.
      2. Attempt full Phase 0 + Phase 1A + Phase 2.
      3. Expected result: MCC processes but the attacker
         cannot produce a valid HMAC without the correct session key,
         OR the attacker can connect since no pre-registration is required,
         BUT the key won't match any fleet aggregation.
    """
    print(f"\n{BOLD}{CYAN}{'='*70}")
    print("  ATTACK 3: UNAUTHORIZED ACCESS  –  Unknown Drone ID")
    print(f"{'='*70}{RESET}\n")

    fake_id = "ROGUE-DRONE-X"

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((MCC_HOST, MCC_PORT))

    # Phase 0
    opcode, payload = recv_message(sock)
    assert opcode == OP_PARAM_INIT
    outer = json.loads(payload)
    params = json.loads(outer["data"])
    p = int(params["p"])
    g = int(params["g"])
    y_mcc = int(params["y_mcc"])

    print(f"{GREEN}[Step 1] Received Phase 0 parameters.{RESET}")

    # Generate rogue keys
    x_rogue, y_rogue = elgamal_keygen(p, g)
    print(f"{YELLOW}[Step 2] Generated rogue keys for '{fake_id}'{RESET}")

    # Phase 1A – Send AUTH_REQ with fake ID
    K_raw = secrets.randbelow(p - 2) + 1
    rn_i = secrets.token_hex(256)
    ts_i = str(time.time())
    c1, c2 = elgamal_encrypt(K_raw, p, g, y_mcc)
    sig_data = (ts_i + rn_i + fake_id + str(c1) + str(c2)).encode()
    sig_r, sig_s = elgamal_sign(sig_data, x_rogue, p, g)

    req = json.dumps({
        "TS_i": ts_i, "RN_i": rn_i, "ID_Di": fake_id,
        "C1": str(c1), "C2": str(c2),
        "sig_r": str(sig_r), "sig_s": str(sig_s),
        "y_drone": str(y_rogue),
    }).encode()
    sock.sendall(pack_message(OP_AUTH_REQ, req))
    print(f"{RED}[Step 3] Sent AUTH_REQ with fake ID '{fake_id}'{RESET}")

    try:
        sock.settimeout(30)
        opcode1b, payload1b = recv_message(sock)

        if opcode1b == OP_ERR_MISMATCH:
            print(f"{GREEN}[RESULT] ✓ MCC REJECTED unauthorized drone!  Reason: {payload1b.decode()}{RESET}")
        elif opcode1b == OP_AUTH_RES:
            print(f"{YELLOW}[Step 4] MCC sent AUTH_RES – proceeding to Phase 2 with wrong key …{RESET}")

            # Try Phase 2 with a deliberately wrong session key
            res = json.loads(payload1b)
            ts_mcc = res["TS_MCC"]
            rn_mcc = res["RN_MCC"]

            # Derive session key (attacker has the real K since they generated it)
            K_bytes = int_to_bytes(K_raw)
            sk = derive_session_key(K_bytes, ts_i, ts_mcc, rn_i, rn_mcc)
            print(f"{YELLOW}  Attacker-derived SK (first 8B): {sk[:8].hex()}{RESET}")

            # Send correct HMAC (attacker knows the key they sent)
            ts_final = str(time.time())
            hmac_data = (fake_id + ts_final).encode()
            hmac_val = compute_hmac(sk, hmac_data)
            confirm = json.dumps({
                "hmac": hmac_val.hex(),
                "TS_final": ts_final,
            }).encode()
            sock.sendall(pack_message(OP_SK_CONFIRM, confirm))

            opcode2, payload2 = recv_message(sock)
            if opcode2 == OP_SUCCESS:
                print(f"{RED}[RESULT] ✗ MCC ACCEPTED the rogue drone '{fake_id}'!{RESET}")
                print(f"{YELLOW}  In a production system, drone IDs should be pre-registered.")
                print(f"  The rogue drone is now in the fleet but any group key broadcast")
                print(f"  will include it, potentially compromising fleet security.{RESET}")
            elif opcode2 == OP_ERR_MISMATCH:
                print(f"{GREEN}[RESULT] ✓ MCC REJECTED at Phase 2! Reason: {payload2.decode()}{RESET}")
            else:
                print(f"{YELLOW}[RESULT] Unexpected opcode at Phase 2: {opcode2}{RESET}")
        else:
            print(f"{YELLOW}[RESULT] Unexpected opcode: {opcode1b}{RESET}")
    except Exception as e:
        print(f"{GREEN}[RESULT] ✓ Connection error: {e}{RESET}")
    finally:
        sock.close()

    print(f"\n{CYAN}Analysis: Without a pre-registration system (PKI / whitelist),")
    print(f"the protocol accepts any drone that can prove possession of a key pair.")
    print(f"In production, drone public keys must be pre-registered with the MCC,")
    print(f"and unknown IDs should be rejected immediately. The current protocol")
    print(f"still provides session key freshness (timestamps/nonces) and HMAC")
    print(f"verification, but doesn't authenticate the drone's *identity* per se.{RESET}\n")


# ═══════════════════════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    attacks = {
        "replay":       attack_replay,
        "mitm":         attack_mitm,
        "unauthorized": attack_unauthorized,
    }

    if len(sys.argv) < 2 or sys.argv[1] not in list(attacks.keys()) + ["all"]:
        print(f"Usage: python attacks.py <{'|'.join(attacks.keys())}|all>")
        sys.exit(1)

    target = sys.argv[1]
    if target == "all":
        for name, fn in attacks.items():
            try:
                fn()
            except Exception as e:
                print(f"{RED}Attack '{name}' crashed: {e}{RESET}")
            print()
    else:
        attacks[target]()


if __name__ == "__main__":
    main()
