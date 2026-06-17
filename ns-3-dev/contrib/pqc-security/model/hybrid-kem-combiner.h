/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#ifndef HYBRID_KEM_COMBINER_H
#define HYBRID_KEM_COMBINER_H

#include "crystals-kyber-kem.h"
#include "hardware-profile.h"
#include "pqc-session-keys.h"
#include "x25519-ecdh.h"

#include "ns3/object.h"
#include "ns3/traced-callback.h"
#include "ns3/type-id.h"

namespace ns3
{
namespace pqc
{

/**
 * \brief The cryptographic mode mapping for experimental evaluation.
 */
enum class CryptoMode
{
    ECC_ONLY,           ///< X25519 ECDH baseline
    KYBER_ONLY,         ///< CRYSTALS-Kyber baseline
    KYBER_CACHED,       ///< CRYSTALS-Kyber with PSK caching optimization
    HYBRID_KYBER_ECDH   ///< Proposed hybrid scheme
};

/**
 * \brief Hybrid KEM combining X25519 ECDH + CRYSTALS-Kyber.
 *
 * Implements the dual-KEM combiner:
 *   shared_secret = HKDF-SHA256(ECDH_ss || Kyber_ss, "Kyber6G-HybridKEM-v1")
 *
 * Security guarantee: the combined secret is secure if EITHER
 * the classical (X25519) or post-quantum (Kyber) scheme remains unbroken.
 * This follows NIST SP 800-56C Rev. 2 hybrid construction guidance.
 *
 * The combiner manages the full lifecycle:
 *   1. Initiator calls GenerateKeyPair() → sends public keys
 *   2. Responder calls Encapsulate() → sends ECDH pub + Kyber ciphertext
 *   3. Initiator calls Decapsulate() → both derive identical session key
 */
class HybridKemCombiner : public Object
{
  public:
    /// Combined key pair (ECDH + Kyber)
    struct HybridKeyPair
    {
        X25519Ecdh::KeyPair ecdhKeys;
        CrystalsKyberKem::KeyPair kyberKeys;
        Time totalGenerationTime;

        /// Total public key wire size (for RRC IE)
        uint32_t TotalPublicKeySize() const
        {
            return static_cast<uint32_t>(ecdhKeys.publicKey.size() +
                                         kyberKeys.publicKey.size());
        }
    };

    /// Result of hybrid encapsulation (responder side)
    struct HybridEncapsResult
    {
        std::vector<uint8_t> ecdhPublicKey;    // 32 bytes
        std::vector<uint8_t> kyberCiphertext;  // 768/1088/1568 bytes
        std::vector<uint8_t> combinedSecret;   // 32 bytes
        Time totalTime;

        /// Total wire size for the response RRC IE
        uint32_t TotalWireSize() const
        {
            return static_cast<uint32_t>(ecdhPublicKey.size() + kyberCiphertext.size());
        }
    };

    static TypeId GetTypeId();

    HybridKemCombiner();
    ~HybridKemCombiner() override;

    /**
     * \brief Set the cryptographic mode to use for evaluation.
     */
    void SetCryptoMode(CryptoMode mode);
    void SetKyberLevel(CrystalsKyberKem::SecurityLevel level);
    void SetHardwareProfile(const HardwareProfile& profile);
    void SetParallelHandshake(bool parallel);

    /**
     * \brief Generate both ECDH and Kyber key pairs (initiator step).
     */
    HybridKeyPair GenerateKeyPair();

    /**
     * \brief Encapsulate toward initiator's public keys (responder step).
     *
     * Performs X25519 DH + Kyber Encaps, combines shared secrets via HKDF.
     * \param initiatorEcdhPk The initiator's X25519 public key
     * \param initiatorKyberPk The initiator's Kyber public key
     * \return Combined encapsulation result
     */
    HybridEncapsResult Encapsulate(const std::vector<uint8_t>& initiatorEcdhPk,
                                    const std::vector<uint8_t>& initiatorKyberPk);

    /**
     * \brief Decapsulate to derive the same combined secret (initiator step).
     *
     * \param myKeys Our hybrid key pair (initiator)
     * \param responderEcdhPk Responder's X25519 public key
     * \param kyberCiphertext Kyber ciphertext from responder
     * \return 32-byte combined shared secret
     */
    std::vector<uint8_t> Decapsulate(const HybridKeyPair& myKeys,
                                      const std::vector<uint8_t>& responderEcdhPk,
                                      const std::vector<uint8_t>& kyberCiphertext);

    /**
     * \brief Derive full PqcSessionKeys from a 32-byte combined secret.
     */
    PqcSessionKeys DeriveSessionKeys(const std::vector<uint8_t>& combinedSecret);

    // ── Trace sources ──
    TracedCallback<Time> m_hybridKeyGenTrace;
    TracedCallback<Time> m_hybridEncapsTrace;
    TracedCallback<Time> m_hybridDecapsTrace;
    TracedCallback<uint32_t> m_totalPublicKeySizeTrace;
    TracedCallback<uint32_t> m_totalEncapsSizeTrace;

  private:
    CryptoMode m_cryptoMode;
    Ptr<X25519Ecdh> m_ecdh;
    Ptr<CrystalsKyberKem> m_kyber;
    HardwareProfile m_hwProfile;
    bool m_parallelHandshake{false};

    Time ScaleTime(Time t) const;
    Time CombineParallelTime(Time a, Time b) const;

    /// Deterministic simulated HKDF-SHA256(ecdhSs || kyberSs, salt)
    static std::vector<uint8_t> SimulatedHkdf(const std::vector<uint8_t>& ecdhSs,
                                              const std::vector<uint8_t>& kyberSs);

    /// Simulation-only: coordinate Kyber/ECDH secrets across encaps/decaps peers
    static std::string SecretCacheKey(const std::vector<uint8_t>& kyberCt);
    static std::map<std::string, std::vector<uint8_t>> s_encapsSecretCache;
};

} // namespace pqc
} // namespace ns3

#endif // HYBRID_KEM_COMBINER_H
