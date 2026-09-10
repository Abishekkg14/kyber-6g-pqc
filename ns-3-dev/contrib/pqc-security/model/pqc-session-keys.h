/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#ifndef PQC_SESSION_KEYS_H
#define PQC_SESSION_KEYS_H

#include "ns3/nstime.h"
#include "ns3/object.h"

#include <cstdint>
#include <vector>

namespace ns3
{
namespace pqc
{

/**
 * \brief Container for session key material derived from hybrid KEM.
 *
 * Holds the 256-bit (32-byte) combined shared secret and derived
 * AES-256-GCM encryption/integrity keys, plus metadata about how
 * and when the keys were established.
 */
struct PqcSessionKeys
{
    /// Combined shared secret: HKDF(ECDH_ss || Kyber_ss)
    std::vector<uint8_t> combinedSecret; // 32 bytes

    /// Derived encryption key for AES-256-GCM (first 32 bytes of KDF output)
    std::vector<uint8_t> encryptionKey; // 32 bytes

    /// Derived integrity key (next 32 bytes of KDF output)
    std::vector<uint8_t> integrityKey; // 32 bytes

    /// Initial nonce / IV base for AES-GCM (12 bytes)
    std::vector<uint8_t> nonceBase; // 12 bytes

    /// Monotonic counter for nonce derivation (prevents nonce reuse)
    uint64_t nonceCounter{0};

    /// Timestamp when these keys were established (simulation time)
    Time establishedAt;

    /// Whether the keys include a Kyber component (true) or ECDH-only (false)
    bool isHybrid{true};

    /// Key generation identifier for forward secrecy tracking
    uint32_t keyGeneration{0};

    /// Returns true if keys have been populated
    bool IsValid() const
    {
        return !combinedSecret.empty() && combinedSecret.size() == 32;
    }

    /// Derive a unique 12-byte nonce for the next packet
    std::vector<uint8_t> NextNonce()
    {
        std::vector<uint8_t> nonce(nonceBase);
        // XOR the counter into the last 8 bytes
        for (int i = 0; i < 8; ++i)
        {
            nonce[4 + i] ^= static_cast<uint8_t>((nonceCounter >> (8 * i)) & 0xFF);
        }
        ++nonceCounter;
        return nonce;
    }

    /// Total overhead added to each PDCP PDU (GCM tag + nonce prefix)
    static constexpr uint32_t PER_PACKET_OVERHEAD = 28; // 16-byte tag + 12-byte nonce
};

/**
 * \brief Payload structure for PQC Information Elements in RRC messages.
 *
 * Carries the public keys, ciphertexts, signatures, and certificates
 * exchanged during RRC Connection Setup or Handover Reconfiguration.
 */
struct PqcRrcIePayload
{
    // ── Key Exchange ──
    std::vector<uint8_t> kyberPublicKey;  // 800/1184/1568 bytes
    std::vector<uint8_t> kyberCiphertext; // 768/1088/1568 bytes
    std::vector<uint8_t> ecdhPublicKey;   // 32 bytes (X25519)

    // ── Authentication ──
    std::vector<uint8_t> mlDsaSignature;   // 2420/3293/4595 bytes
    std::vector<uint8_t> mlDsaCertificate; // 1312/1952/2592 bytes (public key)

    // ── Metadata ──
    bool rejected{false};
    Time processingDelay;

    /// Total wire size of this payload
    uint32_t TotalSize() const
    {
        return static_cast<uint32_t>(kyberPublicKey.size() + kyberCiphertext.size() +
                                     ecdhPublicKey.size() + mlDsaSignature.size() +
                                     mlDsaCertificate.size());
    }

    /// Factory for a rejected payload
    static PqcRrcIePayload Rejected()
    {
        PqcRrcIePayload p;
        p.rejected = true;
        return p;
    }
};

/**
 * \brief Context passed during handover for PQC re-keying.
 */
struct PqcHandoverContext
{
    PqcRrcIePayload targetGnbPayload;  // Target gNB's fresh Kyber PK + ECDH PK
    PqcSessionKeys previousKeys;       // Keys from source gNB (for comparison)
    uint64_t ueImsi{0};
    Time handoverStartTime;
};

} // namespace pqc
} // namespace ns3

#endif // PQC_SESSION_KEYS_H
