/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#ifndef CRYSTALS_KYBER_KEM_H
#define CRYSTALS_KYBER_KEM_H

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
 * \brief Simulated CRYSTALS-Kyber Key Encapsulation Mechanism (FIPS 203).
 *
 * This class does NOT perform real cryptographic operations. Instead, it:
 *   1. Generates random byte arrays of the correct NIST-specified sizes
 *   2. Injects accurate computational delays based on published benchmarks
 *   3. Provides NS-3 trace sources for metrics collection
 *
 * This is the standard approach for network simulation research,
 * allowing accurate measurement of network overhead and latency
 * without requiring a cryptographic library dependency.
 */
class CrystalsKyberKem : public Object
{
  public:
    /// NIST security levels for Kyber (FIPS 203)
    enum SecurityLevel
    {
        KYBER_512 = 0,  ///< NIST Level 1 (~AES-128)
        KYBER_768 = 1,  ///< NIST Level 3 (~AES-192), recommended default
        KYBER_1024 = 2  ///< NIST Level 5 (~AES-256)
    };

    /// Size parameters for each security level (bytes)
    struct Sizes
    {
        uint32_t publicKeySize;
        uint32_t secretKeySize;
        uint32_t ciphertextSize;
        uint32_t sharedSecretSize; // always 32
    };

    /// Result of key generation
    struct KeyPair
    {
        std::vector<uint8_t> publicKey;
        std::vector<uint8_t> secretKey;
        Time generationTime;
    };

    /// Result of encapsulation
    struct EncapsResult
    {
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> sharedSecret;
        Time encapsulationTime;
    };

    /// Result of decapsulation
    struct DecapsResult
    {
        std::vector<uint8_t> sharedSecret;
        Time decapsulationTime;
    };

    /// Approximated LWE Crypto energy in MicroJoules based on NIST submission benchmarks
    struct EnergyMetrics
    {
        double keyGenEnergy; // mJ
        double encapsEnergy; // mJ
        double decapsEnergy; // mJ
    };

    static TypeId GetTypeId();

    CrystalsKyberKem();
    ~CrystalsKyberKem() override;

    /**
     * \brief Generate a Kyber key pair.
     * \return KeyPair with correctly-sized public/secret keys and generation time.
     */
    KeyPair KeyGen();

    /**
     * \brief Encapsulate a shared secret using the recipient's public key.
     * \param publicKey The recipient's Kyber public key.
     * \return EncapsResult with ciphertext, shared secret, and timing.
     */
    EncapsResult Encapsulate(const std::vector<uint8_t>& publicKey);

    /**
     * \brief Decapsulate a shared secret using our secret key and the ciphertext.
     * \param secretKey Our Kyber secret key.
     * \param ciphertext The ciphertext from the sender.
     * \return DecapsResult with shared secret and timing.
     */
    DecapsResult Decapsulate(const std::vector<uint8_t>& secretKey,
                             const std::vector<uint8_t>& ciphertext);

    /**
     * \brief Get the size parameters for the current security level.
     */
    Sizes GetSizes() const;

    /**
     * \brief Get the current security level.
     */
    SecurityLevel GetLevel() const;

    void SetSecurityLevel(SecurityLevel level);

    /**
     * \brief Return the simulated energy metrics (MicroJoules) for the current security level.
     */
    EnergyMetrics GetEnergyMetrics() const;

    // ── Trace sources ──
    TracedCallback<Time> m_keyGenTrace;
    TracedCallback<Time> m_encapsTrace;
    TracedCallback<Time> m_decapsTrace;
    TracedCallback<uint32_t> m_publicKeySizeTrace;
    TracedCallback<uint32_t> m_ciphertextSizeTrace;
    TracedCallback<double> m_energyTrace;
    TracedCallback<uint32_t> m_memoryTrace;

  private:
    SecurityLevel m_level;

    // Timing attributes (configurable via NS-3 attributes)
    Time m_keyGenTime;
    Time m_encapsTime;
    Time m_decapsTime;

    // Random stream for generating dummy key material
    Ptr<UniformRandomVariable> m_rng;

    /// Generate a random byte vector of the given size
    std::vector<uint8_t> GenerateRandomBytes(uint32_t size);

    /// Lookup table for sizes per security level
    static const std::map<SecurityLevel, Sizes> SIZE_TABLE;
};

} // namespace pqc
} // namespace ns3

#endif // CRYSTALS_KYBER_KEM_H
