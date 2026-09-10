/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#include "pqc-handover-manager.h"

#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/uinteger.h"

namespace ns3
{
namespace pqc
{

NS_LOG_COMPONENT_DEFINE("PqcHandoverManager");
NS_OBJECT_ENSURE_REGISTERED(PqcHandoverManager);

TypeId
PqcHandoverManager::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::pqc::PqcHandoverManager")
            .SetParent<Object>()
            .SetGroupName("PqcSecurity")
            .AddConstructor<PqcHandoverManager>()
            .AddAttribute("KeyPoolSize",
                          "Number of pre-computed Kyber key pairs to maintain",
                          UintegerValue(3),
                          MakeUintegerAccessor(&PqcHandoverManager::m_poolTargetSize),
                          MakeUintegerChecker<uint32_t>(1, 10))
            .AddTraceSource("HandoverRekeyLatency",
                            "Time for PQC re-keying during handover",
                            MakeTraceSourceAccessor(
                                &PqcHandoverManager::m_handoverRekeyLatencyTrace),
                            "ns3::Time::TracedCallback")
            .AddTraceSource("HandoverInterruptionTime",
                            "Total data interruption time during handover",
                            MakeTraceSourceAccessor(
                                &PqcHandoverManager::m_handoverInterruptionTimeTrace),
                            "ns3::Time::TracedCallback")
            .AddTraceSource("ForwardSecrecyVerified",
                            "Whether new keys differ from previous (true = FS maintained)",
                            MakeTraceSourceAccessor(
                                &PqcHandoverManager::m_forwardSecrecyVerifiedTrace),
                            "ns3::TracedCallback::Bool")
            .AddTraceSource("HandoverCount",
                            "Number of PQC-rekeyed handovers completed",
                            MakeTraceSourceAccessor(&PqcHandoverManager::m_handoverCountTrace),
                            "ns3::TracedValueCallback::Uint32")
            .AddTraceSource("KeyPoolSize",
                            "Current number of pre-computed key pairs",
                            MakeTraceSourceAccessor(&PqcHandoverManager::m_keyPoolSizeTrace),
                            "ns3::TracedValueCallback::Uint32");

    return tid;
}

PqcHandoverManager::PqcHandoverManager()
    : m_poolTargetSize(3)
{
    m_hybridKem = CreateObject<HybridKemCombiner>();
}

PqcHandoverManager::~PqcHandoverManager()
{
}

void
PqcHandoverManager::SetPdcpLayer(Ptr<PqcPdcpLayer> pdcp)
{
    m_pdcpLayer = pdcp;
}

void
PqcHandoverManager::PrecomputeHandoverKeys()
{
    NS_LOG_INFO("PQC-HO: Pre-computing key pairs (current pool="
                << m_precomputedKeys.size() << " target=" << m_poolTargetSize << ")");

    while (m_precomputedKeys.size() < m_poolTargetSize)
    {
        auto keyPair = m_hybridKem->GenerateKeyPair();
        m_precomputedKeys.push(keyPair);

        NS_LOG_DEBUG("PQC-HO: Pre-computed key pair #" << m_precomputedKeys.size()
                     << " (pk=" << keyPair.TotalPublicKeySize() << "B)");
    }

    m_keyPoolSizeTrace(static_cast<uint32_t>(m_precomputedKeys.size()));
}

PqcSessionKeys
PqcHandoverManager::RapidRekey(const PqcHandoverContext& ctx)
{
    Time rekeyStart = Simulator::Now();
    Time rekeyLatency = Seconds(0);

    NS_LOG_INFO("╔══ PQC Handover Re-Key ══╗");
    NS_LOG_INFO("  IMSI: " << ctx.ueImsi);
    NS_LOG_INFO("  Previous key generation: " << ctx.previousKeys.keyGeneration);

    // 1. Get key pair (from pool if available, otherwise generate)
    HybridKemCombiner::HybridKeyPair localKeys;

    if (!m_precomputedKeys.empty())
    {
        localKeys = m_precomputedKeys.front();
        m_precomputedKeys.pop();
        NS_LOG_INFO("  Using PRE-COMPUTED key pair (pool remaining: "
                     << m_precomputedKeys.size() << ")");
        // No keygen latency since it was pre-computed
    }
    else
    {
        NS_LOG_WARN("  Key pool EMPTY — generating on-the-fly (adds latency)");
        localKeys = m_hybridKem->GenerateKeyPair();
        rekeyLatency += localKeys.totalGenerationTime;
    }

    // 2. Encapsulate toward target gNB's public keys
    auto hybridResult = m_hybridKem->Encapsulate(
        ctx.targetGnbPayload.ecdhPublicKey,
        ctx.targetGnbPayload.kyberPublicKey);
    rekeyLatency += hybridResult.totalTime;

    // 3. Derive new session keys
    PqcSessionKeys newKeys = m_hybridKem->DeriveSessionKeys(hybridResult.combinedSecret);
    newKeys.keyGeneration = ctx.previousKeys.keyGeneration + 1;

    // 4. Verify forward secrecy (new keys must differ from old)
    bool forwardSecure = (newKeys.combinedSecret != ctx.previousKeys.combinedSecret);
    m_forwardSecrecyVerifiedTrace(forwardSecure);

    if (!forwardSecure)
    {
        NS_LOG_WARN("  ⚠ FORWARD SECRECY VIOLATION: new ss == old ss!");
    }
    else
    {
        NS_LOG_INFO("  ✓ Forward secrecy verified (generation "
                     << ctx.previousKeys.keyGeneration << " → " << newKeys.keyGeneration << ")");
    }

    // 5. Install new keys in PDCP layer
    if (m_pdcpLayer)
    {
        m_pdcpLayer->UpdateSessionKeys(newKeys);
    }

    // 6. Update counters
    m_handoverCount++;
    m_lastHandoverTime = Simulator::Now();

    // Calculate total interruption time (includes re-keying + signaling)
    Time interruptionTime = Simulator::Now() - ctx.handoverStartTime;

    NS_LOG_INFO("  Re-key latency: " << rekeyLatency.As(Time::US));
    NS_LOG_INFO("  Total HO interruption: " << interruptionTime.As(Time::MS));
    NS_LOG_INFO("  Handover #" << m_handoverCount);
    NS_LOG_INFO("╚═════════════════════════╝");

    // Fire traces
    m_handoverRekeyLatencyTrace(rekeyLatency);
    m_handoverInterruptionTimeTrace(interruptionTime);
    m_handoverCountTrace(m_handoverCount);
    m_keyPoolSizeTrace(static_cast<uint32_t>(m_precomputedKeys.size()));

    // Refill the pool in the background
    if (m_precomputedKeys.size() < m_poolTargetSize)
    {
        Simulator::Schedule(MicroSeconds(100),
                            &PqcHandoverManager::PrecomputeHandoverKeys,
                            this);
    }

    return newKeys;
}

uint32_t
PqcHandoverManager::GetHandoverCount() const
{
    return m_handoverCount;
}

uint32_t
PqcHandoverManager::GetKeyPoolSize() const
{
    return static_cast<uint32_t>(m_precomputedKeys.size());
}

} // namespace pqc
} // namespace ns3
