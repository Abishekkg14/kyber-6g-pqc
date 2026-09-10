/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#include "quantum-attacker.h"

#include "ns3/boolean.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/uinteger.h"

namespace ns3
{
namespace pqc
{

NS_LOG_COMPONENT_DEFINE("QuantumAttacker");
NS_OBJECT_ENSURE_REGISTERED(QuantumAttacker);

TypeId
QuantumAttacker::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::pqc::QuantumAttacker")
            .SetParent<Application>()
            .SetGroupName("PqcSecurity")
            .AddConstructor<QuantumAttacker>()
            .AddAttribute("CaptureEnabled",
                          "Enable promiscuous packet capture",
                          BooleanValue(true),
                          MakeBooleanAccessor(&QuantumAttacker::m_captureEnabled),
                          MakeBooleanChecker())
            .AddAttribute("MaxCapturePackets",
                          "Maximum number of packets to store (memory limit)",
                          UintegerValue(100000),
                          MakeUintegerAccessor(&QuantumAttacker::m_maxCapturePackets),
                          MakeUintegerChecker<uint32_t>())
            .AddTraceSource("PacketCaptured",
                            "Notification when a packet is captured",
                            MakeTraceSourceAccessor(&QuantumAttacker::m_packetCapturedTrace),
                            "ns3::TracedValueCallback::Uint32")
            .AddTraceSource("DecryptionRate",
                            "Final decryption success rate after quantum attack",
                            MakeTraceSourceAccessor(&QuantumAttacker::m_decryptionRateTrace),
                            "ns3::TracedCallback::Double");

    return tid;
}

QuantumAttacker::QuantumAttacker()
    : m_mode(PASSIVE_CAPTURE),
      m_captureEnabled(true),
      m_maxCapturePackets(100000)
{
}

QuantumAttacker::~QuantumAttacker()
{
}

void
QuantumAttacker::StartApplication()
{
    NS_LOG_INFO("╔══ Quantum Attacker ACTIVATED ══╗");
    NS_LOG_INFO("  Mode: PASSIVE_CAPTURE (HNDL)");
    NS_LOG_INFO("  Strategy: Harvest Now, Decrypt Later");
    NS_LOG_INFO("  Max capture: " << m_maxCapturePackets << " packets");
    NS_LOG_INFO("╚════════════════════════════════╝");

    m_mode = PASSIVE_CAPTURE;
}

void
QuantumAttacker::StopApplication()
{
    NS_LOG_INFO("Quantum Attacker: Capture phase ended. "
                << m_capturedTraffic.size() << " packets captured, "
                << m_capturedHandshakes.size() << " handshakes recorded.");
}

void
QuantumAttacker::PromiscuousSniff(Ptr<const Packet> packet)
{
    if (!m_captureEnabled || m_mode != PASSIVE_CAPTURE)
    {
        return;
    }

    if (m_capturedTraffic.size() >= m_maxCapturePackets)
    {
        return; // Memory limit reached
    }

    CapturedPacket cp;
    cp.captureTime = Simulator::Now();
    cp.packetSize = packet->GetSize();

    // Store a copy of the packet payload
    cp.payload.resize(cp.packetSize);
    packet->CopyData(cp.payload.data(), cp.packetSize);

    m_capturedTraffic.push_back(cp);

    m_packetCapturedTrace(static_cast<uint32_t>(m_capturedTraffic.size()));
}

void
QuantumAttacker::CaptureHandshake(uint64_t imsi, const CapturedHandshake& hs)
{
    m_capturedHandshakes[imsi] = hs;
    NS_LOG_INFO("Quantum Attacker: Captured handshake for IMSI " << imsi
                << " (hybrid=" << hs.isHybrid << ")");
}

QuantumAttacker::DecryptionReport
QuantumAttacker::AttemptRetroactiveDecryption()
{
    m_mode = QUANTUM_DECRYPT;

    DecryptionReport report;
    report.totalCapturedPackets = static_cast<uint32_t>(m_capturedTraffic.size());
    report.totalCapturedHandshakes = static_cast<uint32_t>(m_capturedHandshakes.size());
    report.classicalKeysRecovered = 0;
    report.pqcKeysRecovered = 0;
    report.packetsDecrypted = 0;
    report.packetsFailedDecrypt = 0;

    NS_LOG_INFO("");
    NS_LOG_INFO("╔═══════════════════════════════════════════════════╗");
    NS_LOG_INFO("║  QUANTUM ATTACK — Retroactive Decryption Attempt ║");
    NS_LOG_INFO("╚═══════════════════════════════════════════════════╝");
    NS_LOG_INFO("  Total captured packets: " << report.totalCapturedPackets);
    NS_LOG_INFO("  Total captured handshakes: " << report.totalCapturedHandshakes);
    NS_LOG_INFO("");

    // For each captured handshake, attempt to break the key exchange
    for (auto& [imsi, hs] : m_capturedHandshakes)
    {
        NS_LOG_INFO("  ── IMSI " << imsi << " ──");

        // Step 1: Break classical ECDH (quantum computer can do this)
        // ecdhBroken = true always for a quantum adversary
        NS_LOG_INFO("    X25519 ECDH: BROKEN by quantum computer ✗");

        if (hs.isHybrid)
        {
            // Step 2: Attempt to break Kyber (quantum computer CANNOT do this)
            // kyberBroken = false always; lattice-based, quantum-resistant
            NS_LOG_INFO("    Kyber-768:   SECURE against quantum computer ✓");

            // Hybrid KEM: need BOTH to derive session key
            // K = HKDF(ECDH_ss || Kyber_ss)
            // Attacker has ECDH_ss but NOT Kyber_ss → cannot compute K
            NS_LOG_INFO("    Hybrid key:  CANNOT derive (missing Kyber component)");
            NS_LOG_INFO("    Traffic:     CANNOT decrypt ✓");

            report.classicalKeysRecovered++;
            // pqcKeysRecovered stays 0
        }
        else
        {
            // ECC-only: breaking ECDH is sufficient
            NS_LOG_INFO("    No PQC:      Session key fully recovered!");
            NS_LOG_INFO("    Traffic:     ALL DECRYPTED ✗ (Retroactive attack succeeds)");

            report.classicalKeysRecovered++;
            report.packetsDecrypted += report.totalCapturedPackets /
                                       std::max(1u, report.totalCapturedHandshakes);
        }
    }

    // Calculate final metrics
    report.packetsFailedDecrypt = report.totalCapturedPackets - report.packetsDecrypted;
    report.decryptionSuccessRate =
        (report.totalCapturedPackets > 0)
            ? static_cast<double>(report.packetsDecrypted) / report.totalCapturedPackets
            : 0.0;

    // Generate summary
    NS_LOG_INFO("");
    NS_LOG_INFO("  ═══════════════════════════════════");
    NS_LOG_INFO("  QUANTUM ATTACK REPORT");
    NS_LOG_INFO("  ═══════════════════════════════════");
    NS_LOG_INFO("  Classical keys recovered: " << report.classicalKeysRecovered);
    NS_LOG_INFO("  PQC keys recovered:      " << report.pqcKeysRecovered);
    NS_LOG_INFO("  Packets decrypted:       " << report.packetsDecrypted << "/"
                                               << report.totalCapturedPackets);
    NS_LOG_INFO("  Decryption success rate: " << (report.decryptionSuccessRate * 100.0) << "%");

    if (report.decryptionSuccessRate < 0.01)
    {
        report.summary = "PQC EFFECTIVE: Quantum attacker failed to decrypt any traffic. "
                         "HNDL attack defeated by hybrid ECDH+Kyber KEM.";
        NS_LOG_INFO("  VERDICT: " << report.summary);
    }
    else
    {
        report.summary = "PQC NOT USED: Classical-only key exchange vulnerable to "
                         "retroactive quantum decryption. All captured traffic compromised.";
        NS_LOG_INFO("  VERDICT: " << report.summary);
    }
    NS_LOG_INFO("  ═══════════════════════════════════");

    m_decryptionRateTrace(report.decryptionSuccessRate);

    return report;
}

uint32_t
QuantumAttacker::GetCapturedPacketCount() const
{
    return static_cast<uint32_t>(m_capturedTraffic.size());
}

QuantumAttacker::Mode
QuantumAttacker::GetMode() const
{
    return m_mode;
}

} // namespace pqc
} // namespace ns3
