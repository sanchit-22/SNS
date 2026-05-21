"""
protocol_fsm.py
===============
Implements the protocol finite state machine, including:
- Round tracking
- Key evolution
- Opcode validation
- Session termination logic

Author: CS5.470 Lab Assignment 1
Date: January 2026
"""

import struct
from enum import IntEnum
from typing import Tuple, Optional
from crypto_utils import (
    derive_key, evolve_key, generate_iv,
    aes_cbc_encrypt, aes_cbc_decrypt,
    pkcs7_pad, pkcs7_unpad,
    compute_hmac, verify_hmac
)


# ============================================================================
# Protocol Constants
# ============================================================================

class Opcode(IntEnum):
    """Protocol operation codes"""
    CLIENT_HELLO = 10
    SERVER_CHALLENGE = 20
    CLIENT_DATA = 30
    SERVER_AGGR_RESPONSE = 40
    KEY_DESYNC_ERROR = 50
    TERMINATE = 60


class Direction(IntEnum):
    """Message direction indicators"""
    CLIENT_TO_SERVER = 1
    SERVER_TO_CLIENT = 2


class ProtocolPhase(IntEnum):
    """Protocol session phases"""
    INIT = 0        # Initial state, waiting for CLIENT_HELLO
    ACTIVE = 1      # Active communication
    TERMINATED = 2  # Session terminated


# Message format constants
OPCODE_SIZE = 1
CLIENT_ID_SIZE = 1
ROUND_SIZE = 4
DIRECTION_SIZE = 1
IV_SIZE = 16
HMAC_SIZE = 32

HEADER_SIZE = OPCODE_SIZE + CLIENT_ID_SIZE + ROUND_SIZE + DIRECTION_SIZE + IV_SIZE


# ============================================================================
# Session State Class
# ============================================================================

class SessionState:
    """
    Maintains state for a single client session.
    
    State includes:
    - Current round number
    - Current encryption and MAC keys for both directions
    - Current protocol phase
    - Client ID and master key
    """
    
    def __init__(self, client_id: int, master_key: bytes):
        """
        Initialize a new session state.
        
        Args:
            client_id: Unique client identifier (0-255)
            master_key: Pre-shared symmetric master key
        """
        self.client_id = client_id
        self.master_key = master_key
        self.round = 0
        self.phase = ProtocolPhase.INIT
        
        # Derive initial keys from master key
        # Client-to-Server keys
        self.c2s_enc_key = derive_key(master_key, "C2S-ENC")
        self.c2s_mac_key = derive_key(master_key, "C2S-MAC")
        
        # Server-to-Client keys
        self.s2c_enc_key = derive_key(master_key, "S2C-ENC")
        self.s2c_mac_key = derive_key(master_key, "S2C-MAC")
    
    def get_encryption_key(self, direction: Direction) -> bytes:
        """Get current encryption key for given direction"""
        if direction == Direction.CLIENT_TO_SERVER:
            return self.c2s_enc_key
        else:
            return self.s2c_enc_key
    
    def get_mac_key(self, direction: Direction) -> bytes:
        """Get current MAC key for given direction"""
        if direction == Direction.CLIENT_TO_SERVER:
            return self.c2s_mac_key
        else:
            return self.s2c_mac_key
    
    def evolve_keys_c2s(self, ciphertext: bytes, nonce: bytes):
        """
        Evolve Client-to-Server keys after successful message processing.
        
        Key evolution:
        - C2S_Enc_R+1 = H(C2S_Enc_R || Ciphertext_R)
        - C2S_Mac_R+1 = H(C2S_Mac_R || Nonce_R)
        """
        self.c2s_enc_key = evolve_key(self.c2s_enc_key, ciphertext)
        self.c2s_mac_key = evolve_key(self.c2s_mac_key, nonce)
    
    def evolve_keys_s2c(self, aggregated_data: bytes, status_code: bytes):
        """
        Evolve Server-to-Client keys after successful message processing.
        
        Key evolution:
        - S2C_Enc_R+1 = H(S2C_Enc_R || AggregatedData_R)
        - S2C_Mac_R+1 = H(S2C_Mac_R || StatusCode_R)
        """
        self.s2c_enc_key = evolve_key(self.s2c_enc_key, aggregated_data)
        self.s2c_mac_key = evolve_key(self.s2c_mac_key, status_code)
    
    def advance_round(self):
        """Advance to next round"""
        self.round += 1
    
    def terminate(self):
        """Terminate the session"""
        self.phase = ProtocolPhase.TERMINATED
    
    def is_terminated(self) -> bool:
        """Check if session is terminated"""
        return self.phase == ProtocolPhase.TERMINATED
    
    def activate(self):
        """Transition to ACTIVE phase"""
        self.phase = ProtocolPhase.ACTIVE


# ============================================================================
# Message Construction and Parsing
# ============================================================================

def construct_message(opcode: Opcode, client_id: int, round_num: int, 
                     direction: Direction, plaintext: bytes,
                     enc_key: bytes, mac_key: bytes) -> bytes:
    """
    Construct a protocol message with encryption and authentication.
    
    Message format:
    | Opcode (1) | Client ID (1) | Round (4) | Direction (1) | IV (16) |
    | Ciphertext (variable) | HMAC (32) |
    
    Encryption procedure:
    1. Apply PKCS#7 padding to plaintext
    2. Generate fresh random IV
    3. Encrypt padded plaintext using AES-128-CBC
    4. Construct header
    5. Compute HMAC over (Header || Ciphertext)
    6. Return (Header || Ciphertext || HMAC)
    
    Args:
        opcode: Protocol opcode
        client_id: Client identifier
        round_num: Current round number
        direction: Message direction
        plaintext: Plaintext payload
        enc_key: Encryption key
        mac_key: MAC key
    
    Returns:
        Complete message bytes
    """
    # Step 1: Apply PKCS#7 padding
    padded_plaintext = pkcs7_pad(plaintext)
    
    # Step 2: Generate fresh random IV
    iv = generate_iv()
    
    # Step 3: Encrypt padded plaintext
    ciphertext = aes_cbc_encrypt(padded_plaintext, enc_key, iv)
    
    # Step 4: Construct header
    header = struct.pack('!B B I B 16s', 
                        opcode, 
                        client_id, 
                        round_num, 
                        direction, 
                        iv)
    
    # Step 5: Compute HMAC over (Header || Ciphertext)
    message_for_hmac = header + ciphertext
    hmac_tag = compute_hmac(mac_key, message_for_hmac)
    
    # Step 6: Assemble final message
    full_message = header + ciphertext + hmac_tag
    
    return full_message


def parse_message(message: bytes, expected_round: int, expected_direction: Direction,
                 enc_key: bytes, mac_key: bytes) -> Tuple[int, int, int, bytes]:
    """
    Parse and validate a protocol message.
    
    Decryption procedure:
    1. Extract header fields
    2. Verify round number matches expected
    3. Verify direction matches expected
    4. Extract and verify HMAC (before decryption!)
    5. Decrypt ciphertext if HMAC valid
    6. Remove PKCS#7 padding
    7. Return (opcode, client_id, round, plaintext)
    
    Args:
        message: Complete message bytes
        expected_round: Expected round number
        expected_direction: Expected message direction
        enc_key: Decryption key
        mac_key: MAC key
    
    Returns:
        Tuple of (opcode, client_id, round, plaintext)
    
    Raises:
        ValueError: If any validation fails
    """
    # Check minimum message length
    min_length = HEADER_SIZE + 16 + HMAC_SIZE  # Header + min ciphertext (16 bytes) + HMAC
    if len(message) < min_length:
        raise ValueError(f"Message too short: {len(message)} bytes")
    
    # Step 1: Extract header fields
    opcode, client_id, round_num, direction, iv = struct.unpack(
        '!B B I B 16s', 
        message[:HEADER_SIZE]
    )
    
    # Extract ciphertext and HMAC
    ciphertext = message[HEADER_SIZE:-HMAC_SIZE]
    received_hmac = message[-HMAC_SIZE:]
    
    # Validate ciphertext length (must be multiple of 16)
    if len(ciphertext) % 16 != 0:
        raise ValueError(f"Invalid ciphertext length: {len(ciphertext)}")
    
    # Step 2: Verify round number
    if round_num != expected_round:
        raise ValueError(f"Round mismatch: expected {expected_round}, got {round_num}")
    
    # Step 3: Verify direction
    if direction != expected_direction:
        raise ValueError(f"Direction mismatch: expected {expected_direction}, got {direction}")
    
    # Step 4: Verify HMAC BEFORE decryption (critical for security!)
    message_for_hmac = message[:-HMAC_SIZE]  # Everything except HMAC
    if not verify_hmac(mac_key, message_for_hmac, received_hmac):
        raise ValueError("HMAC verification failed")
    
    # Step 5: Decrypt ciphertext (only after HMAC verification)
    padded_plaintext = aes_cbc_decrypt(ciphertext, enc_key, iv)
    
    # Step 6: Remove PKCS#7 padding
    try:
        plaintext = pkcs7_unpad(padded_plaintext)
    except ValueError as e:
        raise ValueError(f"Padding validation failed: {e}")
    
    return opcode, client_id, round_num, plaintext


# ============================================================================
# Protocol State Machine Validation
# ============================================================================

def validate_opcode_for_phase(opcode: Opcode, phase: ProtocolPhase, is_server: bool) -> bool:
    """
    Validate that an opcode is allowed in the current protocol phase.
    
    State machine rules:
    
    Client side:
    - INIT phase: Can only send CLIENT_HELLO
    - ACTIVE phase: Can only send CLIENT_DATA
    - TERMINATED phase: Cannot send anything
    
    Server side:
    - INIT phase: Can only receive CLIENT_HELLO, send SERVER_CHALLENGE
    - ACTIVE phase: Can receive CLIENT_DATA, send SERVER_AGGR_RESPONSE or KEY_DESYNC_ERROR
    - TERMINATED phase: Can only send TERMINATE
    
    Args:
        opcode: Operation code to validate
        phase: Current protocol phase
        is_server: True if validating for server, False for client
    
    Returns:
        True if opcode is valid for phase, False otherwise
    """
    if phase == ProtocolPhase.TERMINATED:
        # In TERMINATED state, only TERMINATE opcode is allowed
        return opcode == Opcode.TERMINATE
    
    if is_server:
        # Server validation
        if phase == ProtocolPhase.INIT:
            return opcode in [Opcode.CLIENT_HELLO, Opcode.SERVER_CHALLENGE]
        elif phase == ProtocolPhase.ACTIVE:
            return opcode in [Opcode.CLIENT_DATA, Opcode.SERVER_AGGR_RESPONSE, 
                            Opcode.KEY_DESYNC_ERROR]
    else:
        # Client validation
        if phase == ProtocolPhase.INIT:
            return opcode in [Opcode.CLIENT_HELLO, Opcode.SERVER_CHALLENGE]
        elif phase == ProtocolPhase.ACTIVE:
            return opcode in [Opcode.CLIENT_DATA, Opcode.SERVER_AGGR_RESPONSE]
    
    return False


def check_protocol_consistency(session: SessionState, opcode: Opcode, 
                               round_num: int, is_server: bool) -> str:
    """
    Check protocol consistency for incoming message.
    
    Validates:
    1. Session not terminated
    2. Opcode valid for current phase
    3. Round number matches expected
    
    Args:
        session: Current session state
        opcode: Received opcode
        round_num: Received round number
        is_server: True if checking on server side
    
    Returns:
        Empty string if consistent, error message otherwise
    """
    # Check 1: Session not terminated
    if session.is_terminated():
        return "Session already terminated"
    
    # Check 2: Opcode valid for phase
    if not validate_opcode_for_phase(opcode, session.phase, is_server):
        return f"Invalid opcode {opcode} for phase {session.phase}"
    
    # Check 3: Round number matches
    if round_num != session.round:
        return f"Round number mismatch: expected {session.round}, got {round_num}"
    
    return ""  # All checks passed


# ============================================================================
# Protocol Helper Functions
# ============================================================================

def create_error_message(client_id: int, round_num: int, error_msg: str,
                        enc_key: bytes, mac_key: bytes) -> bytes:
    """
    Create a KEY_DESYNC_ERROR message.
    
    Args:
        client_id: Client identifier
        round_num: Current round number
        error_msg: Error message text
        enc_key: Encryption key
        mac_key: MAC key
    
    Returns:
        Complete error message
    """
    plaintext = error_msg.encode('utf-8')
    return construct_message(
        Opcode.KEY_DESYNC_ERROR,
        client_id,
        round_num,
        Direction.SERVER_TO_CLIENT,
        plaintext,
        enc_key,
        mac_key
    )


def create_terminate_message(client_id: int, round_num: int, reason: str,
                            enc_key: bytes, mac_key: bytes, direction: Direction) -> bytes:
    """
    Create a TERMINATE message.
    
    Args:
        client_id: Client identifier
        round_num: Current round number
        reason: Termination reason
        enc_key: Encryption key
        mac_key: MAC key
        direction: Message direction
    
    Returns:
        Complete terminate message
    """
    plaintext = reason.encode('utf-8')
    return construct_message(
        Opcode.TERMINATE,
        client_id,
        round_num,
        direction,
        plaintext,
        enc_key,
        mac_key
    )


# ============================================================================
# Testing Functions
# ============================================================================

if __name__ == "__main__":
    import os
    
    print("Testing Protocol FSM...")
    
    # Test session state initialization
    print("\n1. Testing SessionState initialization...")
    master_key = os.urandom(16)
    session = SessionState(client_id=1, master_key=master_key)
    print(f"   Client ID: {session.client_id}")
    print(f"   Round: {session.round}")
    print(f"   Phase: {session.phase}")
    print(f"   C2S Enc Key: {session.c2s_enc_key.hex()[:32]}...")
    print(f"   C2S MAC Key: {session.c2s_mac_key.hex()[:32]}...")
    assert session.phase == ProtocolPhase.INIT
    print("   ✓ Session initialization test passed")
    
    # Test message construction and parsing
    print("\n2. Testing message construction and parsing...")
    plaintext = b"Hello, Server!"
    message = construct_message(
        Opcode.CLIENT_HELLO,
        session.client_id,
        session.round,
        Direction.CLIENT_TO_SERVER,
        plaintext,
        session.c2s_enc_key,
        session.c2s_mac_key
    )
    print(f"   Message length: {len(message)} bytes")
    print(f"   Message (hex): {message.hex()[:64]}...")
    
    # Parse the message
    opcode, client_id, round_num, decrypted = parse_message(
        message,
        session.round,
        Direction.CLIENT_TO_SERVER,
        session.c2s_enc_key,
        session.c2s_mac_key
    )
    print(f"   Parsed opcode: {opcode}")
    print(f"   Parsed client ID: {client_id}")
    print(f"   Parsed round: {round_num}")
    print(f"   Decrypted: {decrypted}")
    assert decrypted == plaintext
    print("   ✓ Message construction/parsing test passed")
    
    # Test key evolution
    print("\n3. Testing key evolution...")
    old_c2s_enc = session.c2s_enc_key
    old_c2s_mac = session.c2s_mac_key
    
    ciphertext = message[HEADER_SIZE:-HMAC_SIZE]
    nonce = os.urandom(16)
    
    session.evolve_keys_c2s(ciphertext, nonce)
    print(f"   Old C2S Enc: {old_c2s_enc.hex()[:32]}...")
    print(f"   New C2S Enc: {session.c2s_enc_key.hex()[:32]}...")
    assert session.c2s_enc_key != old_c2s_enc
    assert session.c2s_mac_key != old_c2s_mac
    print("   ✓ Key evolution test passed")
    
    # Test protocol phase validation
    print("\n4. Testing protocol phase validation...")
    assert validate_opcode_for_phase(Opcode.CLIENT_HELLO, ProtocolPhase.INIT, False)
    assert not validate_opcode_for_phase(Opcode.CLIENT_DATA, ProtocolPhase.INIT, False)
    assert validate_opcode_for_phase(Opcode.CLIENT_DATA, ProtocolPhase.ACTIVE, False)
    assert validate_opcode_for_phase(Opcode.TERMINATE, ProtocolPhase.TERMINATED, False)
    print("   ✓ Protocol phase validation test passed")
    
    # Test HMAC failure detection
    print("\n5. Testing HMAC failure detection...")
    tampered_message = message[:-1] + bytes([message[-1] ^ 0xFF])
    try:
        parse_message(
            tampered_message,
            session.round,
            Direction.CLIENT_TO_SERVER,
            old_c2s_enc,  # Using old key for this test
            old_c2s_mac
        )
        print("   ✗ HMAC failure should have been detected!")
        assert False
    except ValueError as e:
        print(f"   ✓ HMAC failure correctly detected: {e}")
    
    print("\nAll protocol FSM tests passed!")
