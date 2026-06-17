/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#ifndef ML_DSA_SIGNER_H
#define ML_DSA_SIGNER_H

#include "ns3/nstime.h"
#include "ns3/object.h"
#include "ns3/random-variable-stream.h"
#include "ns3/traced-callback.h"
#include "ns3/type-id.h"

#include <cstdint>
#include <map>
#include <vector>

namespace ns3
{
namespace pqc
{

/**
 * \brief Simulated ML-DSA (CRYSTALS-Dilithium) digital signature scheme (FIPS 204).
 *
 * Provides post-quantum authentication for the hybrid PQC handshake.
 * KEMs alone do not provide authentication — ML-DSA signs the key
 * exchange parameters to prove identity and prevent MITM attacks.
 *
 * Sizes and timing match NIST FIPS 204 specifications.
 */
class MlDsaSigner : public Object
{
  public:
    /// ML-DSA security levels
    enum Level
    {
        ML_DSA_44 = 0, ///< NIST Level 2 (~AES-128 equivalent)
        ML_DSA_65 = 1, ///< NIST Level 3 (~AES-192), recommended
        ML_DSA_87 = 2  ///< NIST Level 5 (~AES-256)
    };

    /// Size parameters per level
    struct Sizes
    {
        uint32_t publicKeySize;
        uint32_t secretKeySize;
        uint32_t signatureSize;
    };

    struct KeyPair
    {
        std::vector<uint8_t> publicKey;
        std::vector<uint8_t> secretKey;
        Time generationTime;
    };

    struct Signature
    {
        std::vector<uint8_t> sigBytes;
        Time signTime;
    };

    struct VerifyResult
    {
        bool valid;
        Time verifyTime;
    };

    static TypeId GetTypeId();

    MlDsaSigner();
    ~MlDsaSigner() override;

    /**
     * \brief Generate an ML-DSA key pair (identity key, typically long-lived).
     */
    KeyPair KeyGen();

    /**
     * \brief Sign a message with our secret key.
     * \param message The data to sign (e.g., concatenated KEM public keys).
     * \return Signature with correctly-sized output and timing.
     */
    Signature Sign(const std::vector<uint8_t>& message);

    /**
     * \brief Verify a signature using the signer's public key.
     * \param message The original message.
     * \param sig The signature to verify.
     * \param publicKey The signer's ML-DSA public key.
     * \return VerifyResult with validity flag and timing.
     */
    VerifyResult Verify(const std::vector<uint8_t>& message,
                        const Signature& sig,
                        const std::vector<uint8_t>& publicKey);

    /**
     * \brief Get the current public key (certificate).
     */
    std::vector<uint8_t> GetPublicKey() const;

    /**
     * \brief Get size parameters for current level.
     */
    Sizes GetSizes() const;

    void SetLevel(Level level);

    // Trace sources
    TracedCallback<Time> m_signTrace;
    TracedCallback<Time> m_verifyTrace;
    TracedCallback<uint32_t> m_signatureSizeTrace;
    TracedCallback<uint32_t> m_publicKeySizeTrace;

  private:
    Level m_level;

    Time m_keyGenTime;
    Time m_signTime;
    Time m_verifyTime;

    KeyPair m_identityKeys; // Long-lived identity key pair
    bool m_keysGenerated{false};

    Ptr<UniformRandomVariable> m_rng;

    std::vector<uint8_t> GenerateRandomBytes(uint32_t size);

    static const std::map<Level, Sizes> SIZE_TABLE;
};

} // namespace pqc
} // namespace ns3

#endif // ML_DSA_SIGNER_H
