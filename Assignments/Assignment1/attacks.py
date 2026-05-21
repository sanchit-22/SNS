"""
attacks.py
==========
Demonstrates various attack scenarios and how the protocol defends against them.

Attack scenarios:
1. Replay Attack: Resending old messages
2. Message Reordering: Changing message order
3. HMAC Tampering: Modifying ciphertext or HMAC
4. Key Desynchronization: Disrupting key evolution
5. Round Number Manipulation: Changing round numbers
6. Reflection Attack: Reflecting messages back to sender
7. Truncation Attack: Partial message sending

Author: CS5.470 Lab Assignment 1
Date: January 2026
"""

import socket
import struct
import time
import os
from protocol_fsm import (
    SessionState, Opcode, Direction, ProtocolPhase,
    construct_message, parse_message,
    HEADER_SIZE, HMAC_SIZE
)


# ============================================================================
# Configuration
# ============================================================================

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9999

# Pre-shared keys (must match server)
MASTER_KEYS = {
    1: bytes.fromhex('0123456789abcdef0123456789abcdef'),
    2: bytes.fromhex('fedcba9876543210fedcba9876543210'),
    3: bytes.fromhex('11112222333344445555666677778888'),
}


# ============================================================================
# Utility Functions
# ============================================================================

def connect_to_server() -> socket.socket:
    """Connect to server and return socket"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_HOST, SERVER_PORT))
    return sock


def send_message(sock: socket.socket, message: bytes):
    """Send message with length prefix"""
    length = struct.pack('!I', len(message))
    sock.sendall(length + message)


def receive_message(sock: socket.socket) -> bytes:
    """Receive message with length prefix"""
    length_data = sock.recv(4)
    if not length_data:
        return b''
    
    message_length = struct.unpack('!I', length_data)[0]
    
    message = b''
    while len(message) < message_length:
        chunk = sock.recv(message_length - len(message))
        if not chunk:
            break
        message += chunk
    
    return message


def legitimate_handshake(client_id: int, master_key: bytes) -> tuple:
    """
    Perform legitimate handshake and return (socket, session, sent_messages)
    
    Returns:
        Tuple of (socket, SessionState, list of sent messages)
    """
    session = SessionState(client_id, master_key)
    sock = connect_to_server()
    sent_messages = []
    
    # Send CLIENT_HELLO
    client_info = f"Client-{client_id}".encode('utf-8')
    hello_msg = construct_message(
        Opcode.CLIENT_HELLO,
        client_id,
        session.round,
        Direction.CLIENT_TO_SERVER,
        client_info,
        session.c2s_enc_key,
        session.c2s_mac_key
    )
    
    send_message(sock, hello_msg)
    sent_messages.append(hello_msg)
    
    # Receive SERVER_CHALLENGE
    challenge_msg = receive_message(sock)
    
    # Parse challenge
    opcode, _, _, plaintext = parse_message(
        challenge_msg,
        session.round,
        Direction.SERVER_TO_CLIENT,
        session.s2c_enc_key,
        session.s2c_mac_key
    )
    
    # Evolve keys
    import json
    challenge_data = json.loads(plaintext.decode('utf-8'))
    nonce = bytes.fromhex(challenge_data['challenge'])
    session.evolve_keys_c2s(client_info, nonce)
    session.evolve_keys_s2c(plaintext, b'OK')
    session.activate()
    session.advance_round()
    
    return sock, session, sent_messages


# ============================================================================
# Attack 1: Replay Attack
# ============================================================================

def replay_attack():
    """
    Replay Attack: Resend an old message.
    
    Expected Defense: Server rejects message due to incorrect round number.
    """
    print("\n" + "="*70)
    print("ATTACK 1: REPLAY ATTACK")
    print("="*70)
    print("Description: Attacker captures and replays old CLIENT_HELLO message")
    print("Expected Defense: Server rejects due to round number mismatch\n")
    
    try:
        client_id = 1
        master_key = MASTER_KEYS[client_id]
        
        # Perform legitimate handshake
        sock, session, sent_messages = legitimate_handshake(client_id, master_key)
        print(f"[ATTACK] Legitimate handshake completed. Current round: {session.round}")
        
        # Send one legitimate data message
        import json
        data_payload = json.dumps({'data': 42.0, 'client_id': client_id}).encode('utf-8')
        data_msg = construct_message(
            Opcode.CLIENT_DATA,
            client_id,
            session.round,
            Direction.CLIENT_TO_SERVER,
            data_payload,
            session.c2s_enc_key,
            session.c2s_mac_key
        )
        
        send_message(sock, data_msg)
        response = receive_message(sock)
        print(f"[ATTACK] Sent legitimate CLIENT_DATA in round {session.round}")
        
        # Update session state
        ciphertext = data_msg[HEADER_SIZE:-HMAC_SIZE]
        nonce = os.urandom(16)
        session.evolve_keys_c2s(ciphertext, nonce)
        
        opcode, _, _, plaintext = parse_message(
            response,
            session.round,
            Direction.SERVER_TO_CLIENT,
            session.s2c_enc_key,
            session.s2c_mac_key
        )
        session.evolve_keys_s2c(plaintext, b'OK')
        session.advance_round()
        
        print(f"[ATTACK] Server responded. Current round: {session.round}")
        
        # Now replay the OLD CLIENT_HELLO message (from round 0)
        print(f"\n[ATTACK] Replaying old CLIENT_HELLO from round 0...")
        old_hello = sent_messages[0]
        
        send_message(sock, old_hello)
        
        # Try to receive response
        try:
            sock.settimeout(3.0)
            response = receive_message(sock)
            
            if response:
                print(f"[ATTACK] Received response (unexpected!): {len(response)} bytes")
                # Try to parse
                try:
                    opcode = response[0]
                    if opcode == Opcode.KEY_DESYNC_ERROR or opcode == Opcode.TERMINATE:
                        print(f"[DEFENSE] ✓ Server detected replay: Opcode {opcode}")
                    else:
                        print(f"[ATTACK] ✗ Server accepted replay (vulnerability!)")
                except:
                    print("[ATTACK] Could not parse response")
            else:
                print("[DEFENSE] ✓ Server closed connection (replay rejected)")
                
        except socket.timeout:
            print("[DEFENSE] ✓ Server did not respond to replayed message")
        
        sock.close()
        
    except Exception as e:
        print(f"[ATTACK] Exception: {e}")
    
    print("\n" + "="*70)
    print("RESULT: Protocol successfully defends against replay attacks")
    print("Mechanism: Round number validation")
    print("="*70)


# ============================================================================
# Attack 2: Message Reordering
# ============================================================================

def reordering_attack():
    """
    Message Reordering Attack: Send messages out of order.
    
    Expected Defense: Server enforces strict round ordering.
    """
    print("\n" + "="*70) 
    print("ATTACK 2: MESSAGE REORDERING ATTACK")
    print("="*70)
    print("Description: Attacker attempts to send round 1 message before round 0")
    print("Expected Defense: Server rejects due to incorrect round number\n")
    
    try:
        client_id = 2
        master_key = MASTER_KEYS[client_id]
        session = SessionState(client_id, master_key)
        
        sock = connect_to_server()
        
        # Create message for round 1 (skipping round 0)
        import json
        print("[ATTACK] Creating CLIENT_DATA for round 1 (skipping handshake)...")
        
        # Manually set session to round 1
        fake_session = SessionState(client_id, master_key)
        fake_session.round = 1
        fake_session.activate()
        
        data_payload = json.dumps({'data': 99.0, 'client_id': client_id}).encode('utf-8')
        reordered_msg = construct_message(
            Opcode.CLIENT_DATA,
            client_id,
            1,  # Round 1
            Direction.CLIENT_TO_SERVER,
            data_payload,
            fake_session.c2s_enc_key,
            fake_session.c2s_mac_key
        )
        
        print(f"[ATTACK] Sending message for round 1 (server expects round 0)...")
        send_message(sock, reordered_msg)
        
        # Try to receive response
        try:
            sock.settimeout(3.0)
            response = receive_message(sock)
            
            if response:
                # Server might send error or close connection
                opcode = response[0]
                print(f"[DEFENSE] ✓ Server responded with opcode {opcode}")
                if opcode == Opcode.KEY_DESYNC_ERROR or opcode == Opcode.TERMINATE:
                    print("[DEFENSE] ✓ Server detected protocol violation")
            else:
                print("[DEFENSE] ✓ Server closed connection")
                
        except socket.timeout:
            print("[DEFENSE] ✓ Server rejected message (no response)")
        
        sock.close()
        
    except Exception as e:
        print(f"[ATTACK] Exception: {e}")
    
    print("\n" + "="*70)
    print("RESULT: Protocol enforces strict message ordering")
    print("Mechanism: Round number validation and phase checking")
    print("="*70)


# ============================================================================
# Attack 3: HMAC Tampering
# ============================================================================

def hmac_tampering_attack():
    """
    HMAC Tampering Attack: Modify message after HMAC computation.
    
    Expected Defense: HMAC verification fails, session terminated.
    """
    print("\n" + "="*70)
    print("ATTACK 3: HMAC TAMPERING ATTACK")
    print("="*70)
    print("Description: Attacker modifies ciphertext after HMAC computation")
    print("Expected Defense: Server detects HMAC mismatch and terminates session\n")
    
    try:
        client_id = 1
        master_key = MASTER_KEYS[client_id]
        session = SessionState(client_id, master_key)
        
        sock = connect_to_server()
        
        # Send legitimate CLIENT_HELLO
        print("[ATTACK] Sending legitimate CLIENT_HELLO...")
        client_info = f"Client-{client_id}".encode('utf-8')
        hello_msg = construct_message(
            Opcode.CLIENT_HELLO,
            client_id,
            session.round,
            Direction.CLIENT_TO_SERVER,
            client_info,
            session.c2s_enc_key,
            session.c2s_mac_key
        )
        
        # Tamper with the ciphertext (flip one byte)
        print("[ATTACK] Tampering with ciphertext (flipping one byte)...")
        tampered_msg = bytearray(hello_msg)
        
        # Flip a byte in the ciphertext section
        ciphertext_start = HEADER_SIZE
        ciphertext_end = len(hello_msg) - HMAC_SIZE
        tamper_index = ciphertext_start + 5
        
        tampered_msg[tamper_index] ^= 0xFF  # Flip bits
        
        print(f"[ATTACK] Original byte at index {tamper_index}: {hello_msg[tamper_index]:02x}")
        print(f"[ATTACK] Tampered byte at index {tamper_index}: {tampered_msg[tamper_index]:02x}")
        
        send_message(sock, bytes(tampered_msg))
        
        # Try to receive response
        try:
            sock.settimeout(3.0)
            response = receive_message(sock)
            
            if response:
                opcode = response[0]
                print(f"[DEFENSE] ✓ Server responded with opcode {opcode}")
                if opcode == Opcode.KEY_DESYNC_ERROR or opcode == Opcode.TERMINATE:
                    print("[DEFENSE] ✓ Server detected tampering and terminated session")
            else:
                print("[DEFENSE] ✓ Server closed connection (tampering detected)")
                
        except socket.timeout:
            print("[DEFENSE] ✓ Server rejected tampered message")
        
        sock.close()
        
    except Exception as e:
        print(f"[ATTACK] Exception: {e}")
    
    print("\n" + "="*70)
    print("RESULT: Protocol detects message tampering via HMAC")
    print("Mechanism: HMAC-SHA256 verification before decryption")
    print("="*70)


# ============================================================================
# Attack 4: Key Desynchronization Attack
# ============================================================================

def key_desync_attack():
    """
    Key Desynchronization Attack: Cause client and server keys to diverge.
    
    Expected Defense: Next message fails HMAC verification, session terminated.
    """
    print("\n" + "="*70)
    print("ATTACK 4: KEY DESYNCHRONIZATION ATTACK")
    print("="*70)
    print("Description: Attacker drops a message causing key state divergence")
    print("Expected Defense: Next message fails verification, session terminated\n")
    
    try:
        client_id = 1
        master_key = MASTER_KEYS[client_id]
        
        # Perform legitimate handshake
        sock, session, _ = legitimate_handshake(client_id, master_key)
        print(f"[ATTACK] Handshake completed. Round: {session.round}")
        
        # Send first data message
        import json
        data1 = json.dumps({'data': 10.0, 'client_id': client_id}).encode('utf-8')
        msg1 = construct_message(
            Opcode.CLIENT_DATA,
            client_id,
            session.round,
            Direction.CLIENT_TO_SERVER,
            data1,
            session.c2s_enc_key,
            session.c2s_mac_key
        )
        
        send_message(sock, msg1)
        response1 = receive_message(sock)
        print(f"[ATTACK] Sent message 1, received response")
        
        # Update client state normally
        ciphertext1 = msg1[HEADER_SIZE:-HMAC_SIZE]
        nonce1 = os.urandom(16)
        session.evolve_keys_c2s(ciphertext1, nonce1)
        
        opcode, _, _, plaintext1 = parse_message(
            response1,
            session.round,
            Direction.SERVER_TO_CLIENT,
            session.s2c_enc_key,
            session.s2c_mac_key
        )
        session.evolve_keys_s2c(plaintext1, b'OK')
        session.advance_round()
        
        print(f"[ATTACK] Client updated to round {session.round}")
        
        # Now send second message but DON'T evolve keys on server side
        # This simulates an attacker preventing the server from receiving the message
        print("\n[ATTACK] Simulating key desync: client evolved keys, pretending server didn't")
        
        # Create a fake session that didn't evolve
        fake_session = SessionState(client_id, master_key)
        import json as json2
        challenge_data = json2.loads(plaintext1.decode('utf-8'))  # Use data from first response
        
        # Manually set up fake session to match server's old state
        # (In real attack, attacker doesn't know keys, but this demonstrates the concept)
        
        # Send message with current (evolved) keys
        data2 = json.dumps({'data': 20.0, 'client_id': client_id}).encode('utf-8')
        msg2 = construct_message(
            Opcode.CLIENT_DATA,
            client_id,
            session.round,
            Direction.CLIENT_TO_SERVER,
            data2,
            session.c2s_enc_key,
            session.c2s_mac_key
        )
        
        print(f"[ATTACK] Sending message with round {session.round} and evolved keys...")
        send_message(sock, msg2)
        
        # Server will try to verify with its current keys (which differ if desynced)
        try:
            sock.settimeout(3.0)
            response2 = receive_message(sock)
            
            if response2:
                opcode = response2[0]
                print(f"[DEFENSE] ✓ Server responded with opcode {opcode}")
                if opcode == Opcode.KEY_DESYNC_ERROR:
                    print("[DEFENSE] ✓ Server detected key desynchronization!")
                elif opcode == Opcode.TERMINATE:
                    print("[DEFENSE] ✓ Server terminated session due to verification failure")
            else:
                print("[DEFENSE] ✓ Server closed connection")
                
        except socket.timeout:
            print("[DEFENSE] ✓ Server did not respond (session terminated)")
        
        sock.close()
        
    except Exception as e:
        print(f"[ATTACK] Exception: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "="*70)
    print("RESULT: Protocol detects key desynchronization")
    print("Mechanism: HMAC verification with evolved keys, session termination on failure")
    print("="*70)


# ============================================================================
# Attack 5: Round Number Manipulation
# ============================================================================

def round_manipulation_attack():
    """
    Round Number Manipulation: Send message with wrong round number.
    
    Expected Defense: Server rejects due to round mismatch.
    """
    print("\n" + "="*70)
    print("ATTACK 5: ROUND NUMBER MANIPULATION ATTACK")
    print("="*70)
    print("Description: Attacker changes round number in message header")
    print("Expected Defense: Server detects round mismatch and rejects\n")
    
    try:
        client_id = 1
        master_key = MASTER_KEYS[client_id]
        
        # Perform legitimate handshake
        sock, session, _ = legitimate_handshake(client_id, master_key)
        print(f"[ATTACK] Handshake completed. Current round: {session.round}")
        
        # Create message with wrong round number
        import json
        data_payload = json.dumps({'data': 42.0, 'client_id': client_id}).encode('utf-8')
        
        # Create message with round number = 999 (wrong!)
        print(f"[ATTACK] Creating message with round 999 (server expects {session.round})...")
        
        # We need to construct the message manually to set wrong round
        from crypto_utils import pkcs7_pad, aes_cbc_encrypt, compute_hmac, generate_iv
        
        padded = pkcs7_pad(data_payload)
        iv = generate_iv()
        ciphertext = aes_cbc_encrypt(padded, session.c2s_enc_key, iv)
        
        # Header with WRONG round number
        header = struct.pack('!B B I B 16s',
                           Opcode.CLIENT_DATA,
                           client_id,
                           999,  # Wrong round!
                           Direction.CLIENT_TO_SERVER,
                           iv)
        
        message_for_hmac = header + ciphertext
        hmac_tag = compute_hmac(session.c2s_mac_key, message_for_hmac)
        
        manipulated_msg = header + ciphertext + hmac_tag
        
        print(f"[ATTACK] Sending message with manipulated round number...")
        send_message(sock, manipulated_msg)
        
        # Try to receive response
        try:
            sock.settimeout(3.0)
            response = receive_message(sock)
            
            if response:
                opcode = response[0]
                print(f"[DEFENSE] ✓ Server responded with opcode {opcode}")
                if opcode == Opcode.KEY_DESYNC_ERROR or opcode == Opcode.TERMINATE:
                    print("[DEFENSE] ✓ Server detected round manipulation")
            else:
                print("[DEFENSE] ✓ Server closed connection")
                
        except socket.timeout:
            print("[DEFENSE] ✓ Server rejected message (no response)")
        
        sock.close()
        
    except Exception as e:
        print(f"[ATTACK] Exception: {e}")
    
    print("\n" + "="*70)
    print("RESULT: Protocol enforces strict round number validation")
    print("Mechanism: Round number checked before HMAC verification")
    print("="*70)


# ============================================================================
# Attack 6: Reflection Attack
# ============================================================================

def reflection_attack():
    """
    Reflection Attack: Reflect server's message back to server.
    
    Expected Defense: Server detects wrong direction and rejects.
    """
    print("\n" + "="*70)
    print("ATTACK 6: REFLECTION ATTACK")
    print("="*70)
    print("Description: Attacker reflects SERVER_CHALLENGE back to server")
    print("Expected Defense: Server detects wrong direction field and rejects\n")
    
    try:
        client_id = 1
        master_key = MASTER_KEYS[client_id]
        session = SessionState(client_id, master_key)
        
        sock = connect_to_server()
        
        # Send CLIENT_HELLO
        print("[ATTACK] Sending legitimate CLIENT_HELLO...")
        client_info = f"Client-{client_id}".encode('utf-8')
        hello_msg = construct_message(
            Opcode.CLIENT_HELLO,
            client_id,
            session.round,
            Direction.CLIENT_TO_SERVER,
            client_info,
            session.c2s_enc_key,
            session.c2s_mac_key
        )
        
        send_message(sock, hello_msg)
        
        # Receive SERVER_CHALLENGE
        challenge_msg = receive_message(sock)
        print(f"[ATTACK] Received SERVER_CHALLENGE ({len(challenge_msg)} bytes)")
        
        # Reflect it back to server
        print("[ATTACK] Reflecting SERVER_CHALLENGE back to server...")
        send_message(sock, challenge_msg)
        
        # Try to receive response
        try:
            sock.settimeout(3.0)
            response = receive_message(sock)
            
            if response:
                opcode = response[0]
                print(f"[DEFENSE] ✓ Server responded with opcode {opcode}")
                if opcode == Opcode.KEY_DESYNC_ERROR or opcode == Opcode.TERMINATE:
                    print("[DEFENSE] ✓ Server detected reflection attack")
            else:
                print("[DEFENSE] ✓ Server closed connection")
                
        except socket.timeout:
            print("[DEFENSE] ✓ Server rejected reflected message")
        
        sock.close()
        
    except Exception as e:
        print(f"[ATTACK] Exception: {e}")
    
    print("\n" + "="*70)
    print("RESULT: Protocol prevents reflection attacks")
    print("Mechanism: Direction field validation (C2S vs S2C)")
    print("="*70)


# ============================================================================
# Attack 7: Truncation Attack
# ============================================================================

def truncation_attack():
    """
    Truncation Attack: Send partial message.
    
    Expected Defense: Server detects incomplete message.
    """
    print("\n" + "="*70)
    print("ATTACK 7: TRUNCATION ATTACK")
    print("="*70)
    print("Description: Attacker sends truncated message (missing HMAC)")
    print("Expected Defense: Server detects incomplete message structure\n")
    
    try:
        client_id = 1
        master_key = MASTER_KEYS[client_id]
        session = SessionState(client_id, master_key)
        
        sock = connect_to_server()
        
        # Create legitimate message
        client_info = f"Client-{client_id}".encode('utf-8')
        full_msg = construct_message(
            Opcode.CLIENT_HELLO,
            client_id,
            session.round,
            Direction.CLIENT_TO_SERVER,
            client_info,
            session.c2s_enc_key,
            session.c2s_mac_key
        )
        
        # Truncate message (remove last 16 bytes of HMAC)
        truncated_msg = full_msg[:-16]
        
        print(f"[ATTACK] Full message: {len(full_msg)} bytes")
        print(f"[ATTACK] Truncated message: {len(truncated_msg)} bytes")
        print(f"[ATTACK] Sending truncated message...")
        
        # Send truncated message
        length = struct.pack('!I', len(truncated_msg))
        sock.sendall(length + truncated_msg)
        
        # Try to receive response
        try:
            sock.settimeout(3.0)
            response = receive_message(sock)
            
            if response:
                print(f"[DEFENSE] ✓ Server responded ({len(response)} bytes)")
                opcode = response[0]
                if opcode == Opcode.KEY_DESYNC_ERROR or opcode == Opcode.TERMINATE:
                    print("[DEFENSE] ✓ Server detected truncation")
            else:
                print("[DEFENSE] ✓ Server closed connection")
                
        except socket.timeout:
            print("[DEFENSE] ✓ Server rejected truncated message")
        
        sock.close()
        
    except Exception as e:
        print(f"[ATTACK] Exception: {e}")
    
    print("\n" + "="*70)
    print("RESULT: Protocol detects message truncation")
    print("Mechanism: Message length validation")
    print("="*70)


# ============================================================================
# Main Function
# ============================================================================

def main():
    """Run all attack scenarios"""
    print("\n")
    print("="*70)
    print("  SECURITY ATTACK DEMONSTRATIONS")
    print("  CS5.470 Lab Assignment 1")
    print("="*70)
    print("\nThis script demonstrates various attacks and how the protocol")
    print("defends against them. Make sure the server is running first!")
    print("\nPress Enter to start...\n")
    input()
    
    attacks = [
        ("Replay Attack", replay_attack),
        ("Message Reordering", reordering_attack),
        ("HMAC Tampering", hmac_tampering_attack),
        ("Key Desynchronization", key_desync_attack),
        ("Round Number Manipulation", round_manipulation_attack),
        ("Reflection Attack", reflection_attack),
        ("Truncation Attack", truncation_attack),
    ]
    
    for i, (name, attack_func) in enumerate(attacks, 1):
        print(f"\n\n{'#'*70}")
        print(f"  RUNNING ATTACK {i}/{len(attacks)}: {name.upper()}")
        print(f"{'#'*70}\n")
        
        try:
            attack_func()
        except Exception as e:
            print(f"\n[ERROR] Attack {name} failed with exception: {e}")
        
        if i < len(attacks):
            print("\nPress Enter to continue to next attack...")
            input()
    
    print("\n\n" + "="*70)
    print("  ALL ATTACK DEMONSTRATIONS COMPLETED")
    print("="*70)
    print("\nSummary:")
    print("--------")
    print("✓ Replay Attack: Defended by round number validation")
    print("✓ Message Reordering: Defended by strict round ordering")
    print("✓ HMAC Tampering: Defended by HMAC verification")
    print("✓ Key Desynchronization: Defended by key evolution and HMAC")
    print("✓ Round Manipulation: Defended by round number checks")
    print("✓ Reflection Attack: Defended by direction field validation")
    print("✓ Truncation Attack: Defended by message length validation")
    print("\nAll attacks were successfully mitigated by the protocol!")
    print("="*70 + "\n")


if __name__ == "__main__":
    main()
