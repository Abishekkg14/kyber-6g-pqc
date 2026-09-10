/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#ifndef PQC_RRC_EXTENSION_H
#define PQC_RRC_EXTENSION_H

#include "hybrid-kem-combiner.h"
#include "hardware-profile.h"
#include "mg1-queue-tracker.h"
#include "ml-dsa-signer.h"
#include "pqc-pdcp-layer.h"
#include "pqc-session-keys.h"
#include "thz-gilbert-elliott-channel.h"
#include "raptor-fountain-coder.h"

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

    /**
     * \brief Set the 5G NR numerology index (mu = 0..5).
     *
     * Determines slot duration T_slot = 1ms / 2^mu and TBS scaling.
     * mu=3 (120 kHz SCS), mu=4 (240 kHz), mu=5 (480 kHz) are typical for FR2/THz.
     */
    void SetNumerology(uint8_t mu);

    /**
     * \brief Enable CSIDH-512 MAC CE bypass.
     *
     * When enabled, public keys are embedded as 64-byte MAC Control Elements
     * instead of RRC IEs, eliminating fragmentation (tau_frag = 0).
     */
    void SetCsidhMacCeBypass(bool enabled);

    /**
     * \brief Attach a Gilbert-Elliott channel model for fragmentation analysis.
     */
    void SetGilbertElliottChannel(Ptr<ThzGilbertElliottChannel> channel);

    /**
     * \brief Attach an M/G/1 queue tracker for service time recording.
     */
    void SetQueueTracker(Ptr<Mg1QueueTracker> tracker);

    /**
     * \brief Enable Application-Layer Rateless Raptor Fountain Coding.
     */
    void SetUseRaptor(bool enabled);

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
    TracedCallback<Time> m_serializationDelayTrace;   // TTI serialization delay
    TracedCallback<uint32_t> m_fragmentCountTrace;    // Fragment count per message

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

    bool m_useRaptor{false};              ///< Whether to use Raptor fountain coding
    Ptr<RaptorFountainCoder> m_coder;     ///< Application-layer fountain coder

    // ── TTI serialization and fragmentation ──
    uint8_t m_numerology{3};              ///< NR numerology index (default mu=3)
    bool m_csidhMacCeBypass{false};       ///< Use 64-byte CSIDH MAC CE instead of RRC IE
    Ptr<ThzGilbertElliottChannel> m_geChannel; ///< Gilbert-Elliott channel model
    Ptr<Mg1QueueTracker> m_queueTracker;  ///< M/G/1 queue tracker

    /**
     * \brief Compute TTI serialization delay for a given payload size.
     *
     * tau_serial(B, mu) = ceil(B / TBS(mu)) * T_slot(mu)
     *
     * \param payloadBytes Total payload size in bytes
     * \return Serialization delay as ns3::Time
     */
    Time ComputeSerializationDelay(uint32_t payloadBytes) const;

    /**
     * \brief Get the Transport Block Size for the current numerology.
     * TBS values from 3GPP TS 38.214 Table 5.1.3.1-2 (MCS 27, 256QAM, 106 PRBs, 2 layers).
     */
    uint32_t GetTbs() const;

    /**
     * \brief Get the slot duration for the current numerology.
     * T_slot = 1ms / 2^mu
     */
    Time GetSlotDuration() const;
};

} // namespace pqc
} // namespace ns3

#endif // PQC_RRC_EXTENSION_H
