/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#ifndef PQC_HANDOVER_MANAGER_H
#define PQC_HANDOVER_MANAGER_H

#include "hybrid-kem-combiner.h"
#include "pqc-pdcp-layer.h"
#include "pqc-session-keys.h"

#include "ns3/object.h"
#include "ns3/traced-callback.h"
#include "ns3/type-id.h"

#include <queue>

namespace ns3
{
namespace pqc
{

/**
 * \brief Forward-secret PQC re-keying during gNB handovers.
 *
 * Manages rapid session key refresh during Xn-based handovers.
 * Ensures forward secrecy by generating fresh Kyber key pairs
 * at each handover — compromising one session key doesn't
 * compromise past or future sessions.
 *
 * Optimization: Pre-computes key material during the A3 event
 * measurement window to minimize the critical-path latency.
 * Only the Kyber encapsulation (~180 µs) is on the critical path.
 */
class PqcHandoverManager : public Object
{
  public:
    static TypeId GetTypeId();

    PqcHandoverManager();
    ~PqcHandoverManager() override;

    /**
     * \brief Set the PDCP layer that needs re-keying.
     */
    void SetPdcpLayer(Ptr<PqcPdcpLayer> pdcp);

    /**
     * \brief Pre-compute Kyber key pairs for upcoming handovers.
     *
     * Called when A3 event triggers (RSRP measurement indicates
     * potential handover). Fills the key pool to avoid generation
     * delay during the actual handover.
     */
    void PrecomputeHandoverKeys();

    /**
     * \brief Perform rapid re-keying during handover.
     *
     * Uses pre-computed keys if available, otherwise generates on-the-fly.
     * Encapsulates toward the target gNB's Kyber public key.
     *
     * \param ctx Handover context (target gNB PQC payload + previous keys).
     * \return New session keys for the target gNB connection.
     */
    PqcSessionKeys RapidRekey(const PqcHandoverContext& ctx);

    /**
     * \brief Get the number of handovers completed.
     */
    uint32_t GetHandoverCount() const;

    /**
     * \brief Get the number of pre-computed key pairs available.
     */
    uint32_t GetKeyPoolSize() const;

    // ── Trace sources ──
    TracedCallback<Time> m_handoverRekeyLatencyTrace;  // PQC re-keying time
    TracedCallback<Time> m_handoverInterruptionTimeTrace;  // Total data interruption
    TracedCallback<bool> m_forwardSecrecyVerifiedTrace; // New keys differ from old
    TracedCallback<uint32_t> m_handoverCountTrace;
    TracedCallback<uint32_t> m_keyPoolSizeTrace;

  private:
    Ptr<PqcPdcpLayer> m_pdcpLayer;
    Ptr<HybridKemCombiner> m_hybridKem;

    // Pre-computed key material pool
    std::queue<HybridKemCombiner::HybridKeyPair> m_precomputedKeys;
    uint32_t m_poolTargetSize;

    // Counters
    uint32_t m_handoverCount{0};
    Time m_lastHandoverTime;
};

} // namespace pqc
} // namespace ns3

#endif // PQC_HANDOVER_MANAGER_H
