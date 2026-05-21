# Security Analysis: Kerberos Under Partial Compromise

## 1. Why One Compromised Authority Cannot Forge Tickets

In our system, a ticket is considered valid **only** if it contains at least **two independent** Schnorr signatures that verify successfully against their respective authority public keys.

Each authority `AS_i` has its own independent key pair `(x_i, y_i)` where `y_i = g^{x_i} mod p`. When authority `AS_i` signs a ticket payload `m`, it generates:
- A fresh random nonce `k_i ∈ Z_q`
- Commitment `R_i = g^{k_i} mod p`
- Challenge `e_i = H(m || R_i || ID_i)`
- Response `s_i = k_i + e_i · x_i mod q`

The signature `(R_i, s_i)` is verified by checking `g^{s_i} ≡ R_i · y_i^{e_i} mod p`.

**If AS1 is compromised**, the attacker has `x_1` and can produce a valid signature binding to `AS1`. However:
- The attacker does **not** know `x_2` or `x_3` (private keys of AS2, AS3)
- Without `x_2` or `x_3`, the attacker **cannot** produce a signature `(R_2, s_2)` that satisfies `g^{s_2} ≡ R_2 · y_2^{e_2} mod p`
- This would require solving the discrete logarithm problem, which is computationally infeasible

Therefore, with only one compromised authority, the attacker can produce at most **one** valid signature — **insufficient** for the 2-of-3 threshold.

## 2. Why Two Compromised Authorities Break Security

If two authorities (e.g., AS1 and AS2) are both compromised, the attacker possesses `x_1` and `x_2`. This allows the attacker to:

1. Create any arbitrary ticket payload `m`
2. Sign it validly as AS1 using `x_1` → produces `(R_1, s_1)`
3. Sign it validly as AS2 using `x_2` → produces `(R_2, s_2)`
4. The ticket now has **2 valid signatures**, meeting the threshold

This is the fundamental limitation of any `t-of-n` threshold scheme: security holds only as long as **at most `t-1`** authorities are compromised. In our 2-of-3 scheme, compromising 2 authorities completely breaks the security guarantee.

## 3. Why Two Independent Schnorr Signatures Prevent Single-Authority Forgery

The security of the multi-signature scheme relies on **independence** of key pairs:

- **No shared secrets**: Each authority generates its own `x_i` independently. Keys are never combined or shared.
- **Independent signing**: Each authority signs with its own nonce `k_i` and private key `x_i`. The challenge includes the authority ID: `e_i = H(m || R_i || ID_i)`.
- **Independent verification**: Each signature is verified against its corresponding public key `y_i`. There is no aggregate verification.

This means an attacker who knows `x_1` gains **zero** information about `x_2` or `x_3`. The security reduces to the standard Schnorr signature security for each individual authority, which in turn relies on the hardness of the discrete logarithm problem.

**Key insight**: Because the challenge includes the authority ID (`ID_i`), a valid signature from AS1 **cannot** be reused as a signature from AS2 — even if the same message is signed. The challenges `e_1 = H(m || R_1 || "AS1")` and `e_2 = H(m || R_2 || "AS2")` are necessarily different.

## 4. Nonce Reuse Risks

**Critical vulnerability**: If an authority reuses a nonce `k` across two different messages, the private key can be recovered.

Given two signatures on messages `m` and `m'` using the same nonce `k`:
- `s  = k + e · x mod q`   where `e  = H(m  || R || ID)`
- `s' = k + e'· x mod q`   where `e' = H(m' || R || ID)`

Subtracting: `s - s' = (e - e') · x mod q`

Therefore: **`x = (s - s') · (e - e')^{-1} mod q`**

This completely reveals the private key `x`, allowing the attacker to forge signatures as that authority for any future message.

**Mitigation**: Our implementation uses `secrets.randbelow(q-1) + 1` for nonce generation, which provides cryptographically secure randomness from the OS. Each call to `schnorr_sign` generates a fresh nonce.

## 5. Key Share Leakage Impact

If one authority's private key `x_i` is leaked:

### Immediate Impact
- The attacker can sign any message as authority `i`
- The attacker can read any data encrypted specifically for authority `i`

### What the Attacker CANNOT Do
- Forge valid tickets (requires 2 signatures, attacker has only 1 key)
- Compromise other authorities' keys (keys are independent)
- Decrypt session keys encrypted for clients (different key material)

### Remediation
1. Revoke the compromised authority's key
2. Increment the `key_version` (tickets signed with old version are rejected)
3. Generate a new key pair for the compromised authority
4. Distribute the new public key to all verifiers

Our system includes a `key_version` field in tickets. Service servers reject tickets with outdated key versions, providing a mechanism for key rotation after compromise.

## 6. Performance Overhead of Multi-Authority Signing

### Computational Costs

| Operation | Single Authority | 2-of-3 Multi-Authority | Overhead |
|-----------|-----------------|----------------------|----------|
| Key Generation | 1 modular exp | 3 modular exp | 3× |
| Signing (per ticket) | 1 modular exp + 1 hash | 2-3 modular exp + 2-3 hashes | 2-3× |
| Verification | 2 modular exp + 1 hash | 4-6 modular exp + 2-3 hashes | 2-3× |

### Network Costs
- **Client → AS**: 3 round-trips instead of 1 (can be parallelized)
- **Client → TGS**: 3 round-trips instead of 1 (can be parallelized)
- **Ticket size**: ~3× larger due to multiple signatures

### Storage Costs
- Each authority stores its own key pair (minimal overhead)
- Tickets carry 2-3 signatures instead of 1

### Latency
- Sequential: ~3× latency per phase
- Parallel (as implemented): latency ≈ max(individual response times)

### Justification
The performance overhead is **modest** (2-3× computational cost) and provides a **critical security guarantee**: resilience to single authority compromise. In practice:
- Modular exponentiation with 512-bit primes takes <1ms
- Network round-trips dominate actual latency
- The security benefit significantly outweighs the performance cost
