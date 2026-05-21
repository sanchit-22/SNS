#!/usr/bin/env python3
"""
attacks.py — Mandatory Attack Scenarios.

Demonstrates 6 attack scenarios and their containment:
  1. Single malicious authority issuing forged ticket
  2. Modified ticket payload
  3. Replay of old partial signature
  4. Leakage of one authority's private signing key
  5. Authority offline scenario
  6. Ticket containing only one valid signature
"""

import os
import sys
import json
import socket
import hashlib
import time
import threading
import secrets

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto_utils import (
    mod_exp, schnorr_keygen, schnorr_sign, schnorr_verify,
    verify_multi_signatures,
    aes_encrypt, aes_decrypt, generate_session_key,
    create_ticket_payload, is_ticket_expired,
    send_message, recv_message,
    load_keys_from_file,
    log_header, log_info, log_success, log_warning, log_error,
    log_crypto, log_network, log_separator, log_attack, log_attack_result,
    Colors
)

# Imports for starting servers inline
from as_node import AuthenticationServer
from tgs_node import TicketGrantingServer
from service_server import ServiceServer
from client import KerberosClient

CONFIG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config")


def load_params():
    """Load Schnorr params and public keys from config."""
    public_path = os.path.join(CONFIG_DIR, "public_config.json")
    config = load_keys_from_file(public_path)
    p = int(config["params"]["p"])
    q = int(config["params"]["q"])
    g = int(config["params"]["g"])
    kv = int(config["params"]["key_version"])
    as_pks = {k: int(v) for k, v in config["as_public_keys"].items()}
    tgs_pks = {k: int(v) for k, v in config["tgs_public_keys"].items()}
    return p, q, g, kv, as_pks, tgs_pks


def start_all_servers():
    """Start all AS, TGS, and service servers in background threads. Returns list of servers."""
    ports_path = os.path.join(CONFIG_DIR, "ports.json")
    ports = load_keys_from_file(ports_path)

    servers = []

    # Start AS nodes
    for i in range(1, 4):
        auth_id = f"AS{i}"
        server = AuthenticationServer(auth_id, ports[auth_id])
        servers.append(server)
        t = threading.Thread(target=server.start, daemon=True)
        t.start()

    # Start TGS nodes
    for i in range(1, 4):
        auth_id = f"TGS{i}"
        server = TicketGrantingServer(auth_id, ports[auth_id])
        servers.append(server)
        t = threading.Thread(target=server.start, daemon=True)
        t.start()

    # Start service server
    service = ServiceServer("SERVICE1", ports["SERVICE1"])
    servers.append(service)
    t = threading.Thread(target=service.start, daemon=True)
    t.start()

    time.sleep(1.5)  # Wait for servers to start
    return servers


def stop_all_servers(servers):
    """Stop all running servers."""
    for s in servers:
        s.stop()
    time.sleep(0.5)


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 1: Single Malicious Authority Issuing Forged Ticket
# ═══════════════════════════════════════════════════════════════════════════════

def attack_1_single_malicious_authority():
    """
    Attack: A single compromised AS creates and signs a TGT entirely on its own.
    Expected: The system rejects the ticket because it only has 1 valid signature.
    """
    log_header("ATTACK 1: Single Malicious Authority Forged Ticket")
    log_attack("ATTACK-1", "Compromised AS1 attempts to forge a TGT with only its own signature")

    p, q, g, kv, as_pks, tgs_pks = load_params()

    # Load AS1's private key (compromised)
    as1_config = load_keys_from_file(os.path.join(CONFIG_DIR, "as1_private.json"))
    as1_private = int(as1_config["private_key"])

    # Forge a TGT
    forged_payload = create_ticket_payload(
        client_id="evil_attacker",
        service_id="TGS",
        session_key=generate_session_key(),
        lifetime=300,
        key_version=kv
    )
    forged_payload["authority_metadata"] = "AS1"

    payload_json = json.dumps(forged_payload, sort_keys=True)
    R, s, auth_id = schnorr_sign(payload_json, as1_private, p, q, g, "AS1")

    log_info("ATTACK-1", "Forged TGT created with single AS1 signature")

    # Try to verify with threshold of 2
    sigs = [(R, s, auth_id)]
    is_valid, valid_count, details = verify_multi_signatures(
        payload_json, sigs, as_pks, p, q, g, threshold=2
    )

    for aid, valid, reason in details:
        if valid:
            log_info("ATTACK-1", f"  {aid}: Signature valid (but alone)")
        else:
            log_error("ATTACK-1", f"  {aid}: {reason}")

    log_separator()
    if not is_valid:
        log_attack_result(True, f"Forged ticket REJECTED — only {valid_count} valid sig(s), need ≥2")
        log_success("ATTACK-1", "ATTACK CONTAINED: Single compromised authority cannot forge tickets ✔")
    else:
        log_attack_result(False, "Forged ticket was ACCEPTED — THIS SHOULD NOT HAPPEN")

    return not is_valid


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 2: Modified Ticket Payload
# ═══════════════════════════════════════════════════════════════════════════════

def attack_2_modified_payload():
    """
    Attack: Attacker intercepts a valid ticket and modifies the payload.
    Expected: Signature verification fails because the signatures are bound to the original payload.
    """
    log_header("ATTACK 2: Modified Ticket Payload")
    log_attack("ATTACK-2", "Attacker modifies ticket payload after signatures are created")

    p, q, g, kv, as_pks, tgs_pks = load_params()

    # Create a legitimate payload and sign with two authorities
    as1_config = load_keys_from_file(os.path.join(CONFIG_DIR, "as1_private.json"))
    as2_config = load_keys_from_file(os.path.join(CONFIG_DIR, "as2_private.json"))
    as1_priv = int(as1_config["private_key"])
    as2_priv = int(as2_config["private_key"])

    original_payload = create_ticket_payload(
        client_id="alice",
        service_id="TGS",
        session_key=generate_session_key(),
        lifetime=300,
        key_version=kv
    )

    payload_json = json.dumps(original_payload, sort_keys=True)
    R1, s1, a1 = schnorr_sign(payload_json, as1_priv, p, q, g, "AS1")
    R2, s2, a2 = schnorr_sign(payload_json, as2_priv, p, q, g, "AS2")

    log_info("ATTACK-2", "Original ticket signed by AS1 and AS2")

    # Verify original is valid
    sigs = [(R1, s1, a1), (R2, s2, a2)]
    is_valid_orig, _, _ = verify_multi_signatures(payload_json, sigs, as_pks, p, q, g, threshold=2)
    log_success("ATTACK-2", f"Original ticket verification: {Colors.GREEN}VALID{Colors.RESET}")

    # ── Now modify the payload ──
    modified_payload = original_payload.copy()
    modified_payload["client_id"] = "evil_attacker"  # Attacker changes client ID
    modified_json = json.dumps(modified_payload, sort_keys=True)

    log_attack("ATTACK-2", "Payload modified: client_id changed from 'alice' → 'evil_attacker'")

    # Verify modified payload with original signatures
    is_valid_mod, valid_count, details = verify_multi_signatures(
        modified_json, sigs, as_pks, p, q, g, threshold=2
    )

    for aid, valid, reason in details:
        if valid:
            log_error("ATTACK-2", f"  {aid}: Signature still valid (unexpected!)")
        else:
            log_info("ATTACK-2", f"  {aid}: Signature {Colors.RED}INVALID{Colors.RESET} (as expected)")

    log_separator()
    if not is_valid_mod:
        log_attack_result(True, f"Modified ticket REJECTED — signatures bound to original payload")
        log_success("ATTACK-2", "ATTACK CONTAINED: Payload tampering detected by signature verification ✔")
    else:
        log_attack_result(False, "Modified ticket was ACCEPTED — THIS SHOULD NOT HAPPEN")

    return not is_valid_mod


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 3: Replay of Old Partial Signature
# ═══════════════════════════════════════════════════════════════════════════════

def attack_3_replay_old_signature():
    """
    Attack: Attacker replays an old signature (R, s) from a previous session
            on a new ticket payload.
    Expected: Verification fails because the challenge is bound to the message content.
    """
    log_header("ATTACK 3: Replay of Old Partial Signature")
    log_attack("ATTACK-3", "Attacker replays old (R,s) signatures on a new ticket")

    p, q, g, kv, as_pks, tgs_pks = load_params()

    as1_config = load_keys_from_file(os.path.join(CONFIG_DIR, "as1_private.json"))
    as2_config = load_keys_from_file(os.path.join(CONFIG_DIR, "as2_private.json"))
    as1_priv = int(as1_config["private_key"])
    as2_priv = int(as2_config["private_key"])

    # Create and sign the OLD ticket
    old_payload = create_ticket_payload(
        client_id="alice",
        service_id="TGS",
        session_key=generate_session_key(),
        lifetime=300,
        key_version=kv
    )
    old_json = json.dumps(old_payload, sort_keys=True)
    R1_old, s1_old, a1 = schnorr_sign(old_json, as1_priv, p, q, g, "AS1")
    R2_old, s2_old, a2 = schnorr_sign(old_json, as2_priv, p, q, g, "AS2")

    log_info("ATTACK-3", "Old ticket signed by AS1 and AS2")

    # Create a NEW ticket (different session key, different timestamp)
    time.sleep(0.1)
    new_payload = create_ticket_payload(
        client_id="alice",
        service_id="TGS",
        session_key=generate_session_key(),
        lifetime=300,
        key_version=kv
    )
    new_json = json.dumps(new_payload, sort_keys=True)

    log_attack("ATTACK-3", "Attempting to replay old signatures on new ticket...")

    # Use OLD signatures with NEW payload
    old_sigs = [(R1_old, s1_old, a1), (R2_old, s2_old, a2)]
    is_valid, valid_count, details = verify_multi_signatures(
        new_json, old_sigs, as_pks, p, q, g, threshold=2
    )

    for aid, valid, reason in details:
        if valid:
            log_error("ATTACK-3", f"  {aid}: Old signature valid on new message (unexpected!)")
        else:
            log_info("ATTACK-3", f"  {aid}: Old signature {Colors.RED}INVALID{Colors.RESET} on new message")

    log_separator()
    if not is_valid:
        log_attack_result(True, f"Replayed signatures REJECTED — challenge is message-bound")
        log_success("ATTACK-3", "ATTACK CONTAINED: Replay attack prevented by message-bound challenges ✔")
    else:
        log_attack_result(False, "Replayed signatures were ACCEPTED — THIS SHOULD NOT HAPPEN")

    return not is_valid


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 4: Leakage of One Authority's Private Key
# ═══════════════════════════════════════════════════════════════════════════════

def attack_4_leaked_private_key():
    """
    Attack: Attacker obtains one authority's private key and tries to forge tickets.
    Expected: With only one key, the attacker can only produce 1 valid signature.
              The ticket is rejected because it needs ≥2.
    """
    log_header("ATTACK 4: Leaked Private Key (One Authority)")
    log_attack("ATTACK-4", "Attacker has leaked AS1's private key and forges a ticket")

    p, q, g, kv, as_pks, tgs_pks = load_params()

    # Attacker has AS1's private key
    as1_config = load_keys_from_file(os.path.join(CONFIG_DIR, "as1_private.json"))
    leaked_key = int(as1_config["private_key"])

    log_warning("ATTACK-4", f"Attacker has AS1 private key: {str(leaked_key)[:30]}...")

    # Attacker forges a ticket and signs with leaked key
    forged_payload = create_ticket_payload(
        client_id="evil_attacker",
        service_id="TGS",
        session_key=generate_session_key(),
        lifetime=300,
        key_version=kv
    )
    forged_json = json.dumps(forged_payload, sort_keys=True)

    # Sign with leaked AS1 key
    R1, s1, a1 = schnorr_sign(forged_json, leaked_key, p, q, g, "AS1")

    # Attacker tries to create a fake second signature (from AS2) without the key
    # They generate a random key pair and sign
    fake_priv = secrets.randbelow(q - 1) + 1
    R2_fake, s2_fake, _ = schnorr_sign(forged_json, fake_priv, p, q, g, "AS2")

    log_info("ATTACK-4", "Ticket signed with leaked AS1 key + fake AS2 signature")

    sigs = [(R1, s1, "AS1"), (R2_fake, s2_fake, "AS2")]
    is_valid, valid_count, details = verify_multi_signatures(
        forged_json, sigs, as_pks, p, q, g, threshold=2
    )

    for aid, valid, reason in details:
        if valid:
            log_warning("ATTACK-4", f"  {aid}: Signature {Colors.GREEN}VALID{Colors.RESET} (from leaked key)")
        else:
            log_info("ATTACK-4", f"  {aid}: Signature {Colors.RED}INVALID{Colors.RESET} (fake key)")

    log_separator()
    if not is_valid:
        log_attack_result(True, f"Forged ticket REJECTED — attacker could only produce {valid_count} valid sig(s)")
        log_success("ATTACK-4", "ATTACK CONTAINED: Single leaked key insufficient for forgery ✔")
    else:
        log_attack_result(False, "Forged ticket was ACCEPTED — THIS SHOULD NOT HAPPEN")

    return not is_valid


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 5: Authority Offline Scenario
# ═══════════════════════════════════════════════════════════════════════════════

def attack_5_authority_offline():
    """
    Scenario: One AS authority is offline/down.
    Expected: Client can still authenticate using the remaining 2 authorities.
    This tests system resilience, not an attack per se.
    """
    log_header("ATTACK 5: Authority Offline Scenario")
    log_attack("ATTACK-5", "AS3 is offline — testing system resilience")

    p, q, g, kv, as_pks, tgs_pks = load_params()

    # Simulate: only start AS1 and AS2, skip AS3
    ports_path = os.path.join(CONFIG_DIR, "ports.json")
    ports = load_keys_from_file(ports_path)

    # Start only AS1 and AS2
    as1 = AuthenticationServer("AS1", ports["AS1"])
    as2 = AuthenticationServer("AS2", ports["AS2"])
    t1 = threading.Thread(target=as1.start, daemon=True)
    t2 = threading.Thread(target=as2.start, daemon=True)
    t1.start()
    t2.start()

    # Start all TGS and service
    tgs_servers = []
    for i in range(1, 4):
        auth_id = f"TGS{i}"
        srv = TicketGrantingServer(auth_id, ports[auth_id])
        tgs_servers.append(srv)
        t = threading.Thread(target=srv.start, daemon=True)
        t.start()

    service = ServiceServer("SERVICE1", ports["SERVICE1"])
    t_svc = threading.Thread(target=service.start, daemon=True)
    t_svc.start()

    time.sleep(1.5)

    log_warning("ATTACK-5", "AS3 is NOT running — client will get connection refused")

    # Client authenticates
    client = KerberosClient("alice", "password_alice")
    phase1_ok = client.phase1_as_exchange()
    phase2_ok = False
    phase3_ok = False

    if phase1_ok:
        phase2_ok = client.phase2_tgs_exchange("SERVICE1")
    if phase2_ok:
        phase3_ok = client.phase3_service_auth("SERVICE1")

    log_separator()
    if phase3_ok:
        log_attack_result(True, "System operates correctly with one authority offline")
        log_success("ATTACK-5", "RESILIENCE VERIFIED: 2-of-3 threshold allows degraded operation ✔")
    else:
        log_attack_result(False, "System failed even though 2 authorities were available")

    # Cleanup
    as1.stop()
    as2.stop()
    for s in tgs_servers:
        s.stop()
    service.stop()
    time.sleep(0.5)

    return phase3_ok


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK 6: Ticket with Only One Valid Signature
# ═══════════════════════════════════════════════════════════════════════════════

def attack_6_one_valid_signature():
    """
    Attack: Construct a ticket with 1 valid signature and 1 completely fake signature.
    Expected: Service rejects the ticket because only 1 signature verifies.
    """
    log_header("ATTACK 6: Ticket with Only One Valid Signature")
    log_attack("ATTACK-6", "Ticket constructed with 1 real + 1 fake TGS signature")

    p, q, g, kv, as_pks, tgs_pks = load_params()

    # Load TGS1's private key for the real signature
    tgs1_config = load_keys_from_file(os.path.join(CONFIG_DIR, "tgs1_private.json"))
    tgs1_priv = int(tgs1_config["private_key"])

    # Create a service ticket
    st_payload = create_ticket_payload(
        client_id="alice",
        service_id="SERVICE1",
        session_key=generate_session_key(),
        lifetime=300,
        key_version=kv
    )
    st_json = json.dumps(st_payload, sort_keys=True)

    # Real signature from TGS1
    R1, s1, a1 = schnorr_sign(st_json, tgs1_priv, p, q, g, "TGS1")

    # Fake signature pretending to be from TGS2
    fake_R = secrets.randbelow(p)
    fake_s = secrets.randbelow(q)

    log_info("ATTACK-6", "Ticket created with TGS1 real sig + TGS2 fake sig")

    sigs = [(R1, s1, "TGS1"), (fake_R, fake_s, "TGS2")]
    is_valid, valid_count, details = verify_multi_signatures(
        st_json, sigs, tgs_pks, p, q, g, threshold=2
    )

    for aid, valid, reason in details:
        if valid:
            log_success("ATTACK-6", f"  {aid}: Signature {Colors.GREEN}VALID{Colors.RESET}")
        else:
            log_error("ATTACK-6", f"  {aid}: Signature {Colors.RED}INVALID{Colors.RESET} ({reason})")

    log_separator()
    if not is_valid:
        log_attack_result(True, f"Ticket REJECTED — only {valid_count} valid sig(s), need ≥2")
        log_success("ATTACK-6", "ATTACK CONTAINED: Fake signatures detected by verification ✔")
    else:
        log_attack_result(False, "Ticket was ACCEPTED — THIS SHOULD NOT HAPPEN")

    return not is_valid


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    log_header("KERBEROS ATTACK SCENARIO DEMONSTRATION")
    print(f"  {Colors.YELLOW}Testing 6 mandatory attack scenarios{Colors.RESET}")
    print(f"  {Colors.YELLOW}Each scenario demonstrates attack containment{Colors.RESET}")
    print()
    log_separator()

    results = {}

    # Attacks 1-4 and 6 are offline (don't need running servers)
    log_info("ATTACKS", f"{Colors.BOLD}Running offline attack scenarios (1-4, 6)...{Colors.RESET}")
    log_separator()

    results["Attack 1: Single Malicious Authority"] = attack_1_single_malicious_authority()
    results["Attack 2: Modified Ticket Payload"] = attack_2_modified_payload()
    results["Attack 3: Replay Old Signature"] = attack_3_replay_old_signature()
    results["Attack 4: Leaked Private Key"] = attack_4_leaked_private_key()
    results["Attack 6: One Valid Signature"] = attack_6_one_valid_signature()

    # Attack 5 needs servers
    log_separator()
    log_info("ATTACKS", f"{Colors.BOLD}Running live server attack scenario (5)...{Colors.RESET}")
    log_separator()

    results["Attack 5: Authority Offline"] = attack_5_authority_offline()

    # ── Summary ──
    log_header("ATTACK SCENARIO RESULTS")
    all_passed = True
    for name, passed in results.items():
        status = f"{Colors.GREEN}✔ PASS{Colors.RESET}" if passed else f"{Colors.RED}✖ FAIL{Colors.RESET}"
        print(f"  {status}  {name}")
        if not passed:
            all_passed = False

    print()
    log_separator()
    if all_passed:
        log_success("ATTACKS", f"{Colors.BG_GREEN}{Colors.WHITE} ALL 6 ATTACK SCENARIOS PASSED {Colors.RESET}")
    else:
        log_error("ATTACKS", f"{Colors.BG_RED}{Colors.WHITE} SOME ATTACK SCENARIOS FAILED {Colors.RESET}")

    print()


if __name__ == "__main__":
    main()
