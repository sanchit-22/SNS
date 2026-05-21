#!/usr/bin/env python3
"""
master_keygen.py — Generate Schnorr key pairs for all authorities.

Generates:
  - Shared Schnorr parameters (p, q, g)
  - Independent key pairs (x_i, y_i) for AS1, AS2, AS3
  - Independent key pairs for TGS1, TGS2, TGS3
  - Saves to config files for each authority
"""

import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto_utils import (
    generate_schnorr_params, schnorr_keygen, save_keys_to_file,
    log_header, log_info, log_success, log_crypto, log_separator, Colors
)

# Output directory for key files
CONFIG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config")
KEY_VERSION = 1


def main():
    log_header("MASTER KEY GENERATION")

    # Create config directory
    os.makedirs(CONFIG_DIR, exist_ok=True)
    log_info("KEYGEN", f"Config directory: {CONFIG_DIR}")
    log_separator()

    # ── Generate shared Schnorr parameters ──
    p, q, g = generate_schnorr_params(bit_length=512)
    log_separator()

    params = {
        "p": str(p),
        "q": str(q),
        "g": str(g),
        "key_version": KEY_VERSION
    }

    # ── Generate AS key pairs ──
    log_info("KEYGEN", f"{Colors.BOLD}Generating AS authority keys...{Colors.RESET}")
    as_public_keys = {}
    for i in range(1, 4):
        auth_id = f"AS{i}"
        x, y = schnorr_keygen(p, q, g)
        as_public_keys[auth_id] = str(y)

        # Save private key for this authority
        private_config = {
            "authority_id": auth_id,
            "private_key": str(x),
            "public_key": str(y),
            "params": params
        }
        filepath = os.path.join(CONFIG_DIR, f"{auth_id.lower()}_private.json")
        save_keys_to_file(filepath, private_config)
        log_crypto("KEYGEN", f"{auth_id}: Key pair generated → {filepath}")

    log_separator()

    # ── Generate TGS key pairs ──
    log_info("KEYGEN", f"{Colors.BOLD}Generating TGS authority keys...{Colors.RESET}")
    tgs_public_keys = {}
    for i in range(1, 4):
        auth_id = f"TGS{i}"
        x, y = schnorr_keygen(p, q, g)
        tgs_public_keys[auth_id] = str(y)

        private_config = {
            "authority_id": auth_id,
            "private_key": str(x),
            "public_key": str(y),
            "params": params
        }
        filepath = os.path.join(CONFIG_DIR, f"{auth_id.lower()}_private.json")
        save_keys_to_file(filepath, private_config)
        log_crypto("KEYGEN", f"{auth_id}: Key pair generated → {filepath}")

    log_separator()

    # ── Save shared public config ──
    public_config = {
        "params": params,
        "as_public_keys": as_public_keys,
        "tgs_public_keys": tgs_public_keys,
        "key_version": KEY_VERSION
    }
    public_path = os.path.join(CONFIG_DIR, "public_config.json")
    save_keys_to_file(public_path, public_config)
    log_success("KEYGEN", f"Public config saved → {public_path}")

    # ── Save AS ports config ──
    ports_config = {
        "AS1": 5001, "AS2": 5002, "AS3": 5003,
        "TGS1": 6001, "TGS2": 6002, "TGS3": 6003,
        "SERVICE1": 7001
    }
    ports_path = os.path.join(CONFIG_DIR, "ports.json")
    save_keys_to_file(ports_path, ports_config)
    log_success("KEYGEN", f"Ports config saved → {ports_path}")

    log_separator()
    log_header("KEY GENERATION COMPLETE")

    # Print summary
    print(f"  {Colors.GREEN}✔ Schnorr Parameters{Colors.RESET}: p ({p.bit_length()} bits), q ({q.bit_length()} bits)")
    print(f"  {Colors.GREEN}✔ AS Authorities{Colors.RESET}    : AS1, AS2, AS3")
    print(f"  {Colors.GREEN}✔ TGS Authorities{Colors.RESET}   : TGS1, TGS2, TGS3")
    print(f"  {Colors.GREEN}✔ Key Version{Colors.RESET}       : {KEY_VERSION}")
    print(f"  {Colors.GREEN}✔ Config Dir{Colors.RESET}        : {CONFIG_DIR}")
    print()


if __name__ == "__main__":
    main()
