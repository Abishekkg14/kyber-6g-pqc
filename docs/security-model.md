# Security Model

## Hybrid KEM construction

```
shared_secret = HKDF-SHA256(ECDH_ss || Kyber_ss, "Kyber6G-HybridKEM-v1")  [simulated deterministic mix]
```

Security guarantee: session key remains secure if **either** X25519 or Kyber remains unbroken (NIST SP 800-56C hybrid guidance).

## RRC → PDCP key flow

1. UE `GenerateConnectionRequest()` — hybrid keygen + ML-DSA sign
2. gNB `ProcessConnectionRequest()` — verify, encapsulate, derive keys
3. UE `CompleteKeyExchange()` — decapsulate matching combined secret
4. `DeriveSessionKeys()` — encryption key, integrity key, nonce base → `PqcPdcpLayer::InstallSessionKeys`

5G-AKA extension point: combined secret feeds the same KDF chain as classical KASME derivation in a full EPC integration; this simulation documents the IE extension without running EAP-AKA.

## Mobility-aware cache

`PqcKeyCache` entries: `{keyId, combinedSecret, createdAt, ttl, mobilityHash, revoked}`.

| Control | Behavior |
|---------|----------|
| TTL expiry | `stale_key_events`, full re-handshake |
| Revocation | `PurgeCache()` / `Revoke()`, blocks reuse |
| Mobility hash mismatch | Treated as stale |
| Replay nonce | `ValidateNonce()` rejects duplicates |

## Threat assumptions

- **Honest but curious gNB** with passive harvest (quantum attacker model)
- **No active MITM** on ML-DSA verify path (simulation accepts well-formed sigs)
- **Cache poisoning** mitigated by TTL + revocation + mobility binding

## Bit-security metadata

Documented constants in `PqcSecurityHelper::GetSecurityBits()` — not cryptanalytic simulation.
