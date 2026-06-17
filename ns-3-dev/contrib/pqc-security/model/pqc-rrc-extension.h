/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#ifndef PQC_RRC_EXTENSION_H
#define PQC_RRC_EXTENSION_H

#include "hybrid-kem-combiner.h"
#include "hardware-profile.h"
#include "ml-dsa-signer.h"
#include "pqc-pdcp-layer.h"
#include "pqc-session-keys.h"

#include "ns3/object.h"
#include "ns3/traced-callback.h"
#include "ns3/type-id.h"

namespace ns3
{
namespace pqc
{

/**
 * \brief PQC extension for 5G NR RRC connection setup and handover.
 *
 * Implements the hybrid PQC handshake protocol:
 *   1. UE generates ECDH + Kyber key pairs, signs with ML-DSA
 *   2. gNB verifies signature, encapsulates (ECDH DH + Kyber Encaps)
 *   3. UE decapsulates, both derive identical session keys via HKDF
 *   4. Session keys are installed in PqcPdcpLayer for data encryption
 *
 * Wire sizes per handshake (Kyber-768 + ML-DSA-65):
 *   RRC Connection Request:  ~6,461 bytes
 *   RRC Connection Setup:    ~4,413 bytes
 *   Total handshake:        ~10,874 bytes (vs ~300B classical)
 */
class PqcRrcExtension : public Object
{
  public:
    /// Role of this instance
    enum Role
    {
        UE_ROLE = 0,  ///< User Equipment (initiator)
        GNB_ROLE = 1  ///< gNodeB (responder)
    };

    static TypeId GetTypeId();

    PqcRrcExtension();
    ~PqcRrcExtension() override;

    /**
     * \brief Set the role (UE or gNB) of this extension.
     */
    void SetRole(Role role);

    /**
     * \brief Set the PDCP layer to install session keys into.
     */
    void SetPdcpLayer(Ptr<PqcPdcpLayer> pdcp);

    /**
     * \brief Set the crypto mode for evaluation.
     */
    void SetCryptoMode(CryptoMode mode);

    void SetKyberLevel(CrystalsKyberKem::SecurityLevel level);
    void SetMlDsaLevel(MlDsaSigner::Level level);
    void SetHardwareProfile(const HardwareProfile& profile);
    void SetParallelHandshake(bool parallel);

    // ═══════════════════════════════════════════════════
    // UE-side methods (initiator)
    // ═══════════════════════════════════════════════════

    /**
     * \brief Generate PQC RRC Connection Request payload (UE side).
     *
     * Generates hybrid key pair and ML-DSA signature.
     * \return PqcRrcIePayload containing public keys + signature.
     */
    PqcRrcIePayload GenerateConnectionRequest();

    /**
     * \brief Complete key exchange upon receiving gNB's response (UE side).
     *
     * Decapsulates Kyber ciphertext, computes ECDH DH, derives session keys.
     * \param gnbResponse The gNB's RRC Connection Setup PQC payload.
     * \return Derived session keys (also installed in PDCP layer).
     */
    PqcSessionKeys CompleteKeyExchange(const PqcRrcIePayload& gnbResponse);

    // ═══════════════════════════════════════════════════
    // gNB-side methods (responder)
    // ═══════════════════════════════════════════════════

    /**
     * \brief Process UE's connection request and generate response (gNB side).
     *
     * Verifies ML-DSA signature, performs hybrid encapsulation,
     * derives session keys.
     * \param uePayload The UE's RRC Connection Request PQC payload.
     * \return PqcRrcIePayload containing ciphertext + signature.
     */
    PqcRrcIePayload ProcessConnectionRequest(const PqcRrcIePayload& uePayload);

    // ═══════════════════════════════════════════════════
    // Common methods
    // ═══════════════════════════════════════════════════

    /**
     * \brief Get the session keys (after handshake completion).
     */
    PqcSessionKeys GetSessionKeys() const;

    /**
     * \brief Check if the handshake has completed.
     */
    bool IsHandshakeComplete() const;

    /**
     * \brief Get total bytes sent in the handshake.
     */
    uint32_t GetHandshakeBytesSent() const;

    /**
     * \brief Get total processing time for the handshake.
     */
    Time GetHandshakeProcessingTime() const;

    // ── Trace sources ──
    TracedCallback<uint32_t> m_rrcRequestSizeTrace;  // Total request IE size
    TracedCallback<uint32_t> m_rrcSetupSizeTrace;    // Total setup IE size
    TracedCallback<Time> m_handshakeLatencyTrace;     // Total handshake time
    TracedCallback<Time> m_processingTimeTrace;       // Crypto processing only
    TracedCallback<bool> m_authResultTrace;           // ML-DSA verification result

  private:
    Role m_role;
    Ptr<HybridKemCombiner> m_hybridKem;
    Ptr<MlDsaSigner> m_signer;
    Ptr<MlDsaSigner> m_verifier; // Separate instance for verification
    Ptr<PqcPdcpLayer> m_pdcpLayer;

    // State
    HybridKemCombiner::HybridKeyPair m_localKeys;
    PqcSessionKeys m_sessionKeys;
    bool m_handshakeComplete{false};
    uint32_t m_bytesSent{0};
    Time m_totalProcessingTime;
    Time m_handshakeStartTime;

    CryptoMode m_cryptoMode;
    bool m_enableAuth; // Whether ML-DSA authentication is enabled
};

} // namespace pqc
} // namespace ns3

#endif // PQC_RRC_EXTENSION_H
