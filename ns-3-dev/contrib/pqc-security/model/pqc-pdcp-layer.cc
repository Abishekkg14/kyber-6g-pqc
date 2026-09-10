/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#include "pqc-pdcp-layer.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

namespace ns3
{
namespace pqc
{

NS_LOG_COMPONENT_DEFINE("PqcPdcpLayer");
NS_OBJECT_ENSURE_REGISTERED(PqcPdcpLayer);

TypeId
PqcPdcpLayer::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::pqc::PqcPdcpLayer")
            .SetParent<Object>()
            .SetGroupName("PqcSecurity")
            .AddConstructor<PqcPdcpLayer>()
            .AddTraceSource("TxOverhead",
                            "Per-packet TX overhead (original, encrypted sizes)",
                            MakeTraceSourceAccessor(&PqcPdcpLayer::m_txOverheadTrace),
                            "ns3::TracedCallback::Uint32Uint32")
            .AddTraceSource("RxOverhead",
                            "Per-packet RX overhead (encrypted, decrypted sizes)",
                            MakeTraceSourceAccessor(&PqcPdcpLayer::m_rxOverheadTrace),
                            "ns3::TracedCallback::Uint32Uint32")
            .AddTraceSource("EncryptLatency",
                            "Per-packet encryption latency",
                            MakeTraceSourceAccessor(&PqcPdcpLayer::m_encryptLatencyTrace),
                            "ns3::Time::TracedCallback")
            .AddTraceSource("DecryptLatency",
                            "Per-packet decryption latency",
                            MakeTraceSourceAccessor(&PqcPdcpLayer::m_decryptLatencyTrace),
                            "ns3::Time::TracedCallback")
            .AddTraceSource("KeyGeneration",
                            "Key generation counter (for forward secrecy tracking)",
                            MakeTraceSourceAccessor(&PqcPdcpLayer::m_keyGenerationTrace),
                            "ns3::TracedValueCallback::Uint32");

    return tid;
}

PqcPdcpLayer::PqcPdcpLayer()
    : m_mode(TRANSPARENT)
{
    m_cipher = CreateObject<AesGcmCipher>();
}

PqcPdcpLayer::~PqcPdcpLayer()
{
}

void
PqcPdcpLayer::InstallSessionKeys(const PqcSessionKeys& keys)
{
    m_sessionKeys = keys;
    m_cipher->InstallKeys(keys);
    m_mode = ENCRYPTED;

    NS_LOG_INFO("PQC-PDCP: Session keys installed, mode=ENCRYPTED, generation="
                << keys.keyGeneration << " hybrid=" << keys.isHybrid
                << " at t=" << Simulator::Now().As(Time::MS));

    m_keyGenerationTrace(keys.keyGeneration);
}

void
PqcPdcpLayer::UpdateSessionKeys(const PqcSessionKeys& newKeys)
{
    PqcSessionKeys updatedKeys = newKeys;
    updatedKeys.keyGeneration = m_sessionKeys.keyGeneration + 1;

    m_sessionKeys = updatedKeys;
    m_cipher->InstallKeys(updatedKeys);

    NS_LOG_INFO("PQC-PDCP: Session keys UPDATED (handover re-key), generation="
                << updatedKeys.keyGeneration
                << " at t=" << Simulator::Now().As(Time::MS));

    m_keyGenerationTrace(updatedKeys.keyGeneration);
}

Ptr<Packet>
PqcPdcpLayer::ProcessTxSdu(Ptr<Packet> packet)
{
    if (m_mode == TRANSPARENT)
    {
        NS_LOG_DEBUG("PQC-PDCP TX: TRANSPARENT mode, passing through");
        return packet;
    }

    uint32_t originalSize = packet->GetSize();

    // Serialize packet content for "encryption"
    std::vector<uint8_t> plaintext(originalSize);
    packet->CopyData(plaintext.data(), originalSize);

    // Encrypt via AES-GCM (simulated)
    auto encResult = m_cipher->Encrypt(plaintext);

    // Create new packet with encrypted content
    Ptr<Packet> encPacket = Create<Packet>(encResult.ciphertext.data(),
                                            static_cast<uint32_t>(encResult.ciphertext.size()));

    // Update counters
    m_totalOverheadBytes += encResult.overhead;
    m_packetsEncrypted++;

    // Fire traces
    m_txOverheadTrace(originalSize, encPacket->GetSize());
    m_encryptLatencyTrace(encResult.encryptTime);

    NS_LOG_DEBUG("PQC-PDCP TX: " << originalSize << "B -> " << encPacket->GetSize()
                                  << "B (+" << encResult.overhead << "B overhead)");

    return encPacket;
}

Ptr<Packet>
PqcPdcpLayer::ProcessRxPdu(Ptr<Packet> packet)
{
    if (m_mode == TRANSPARENT)
    {
        NS_LOG_DEBUG("PQC-PDCP RX: TRANSPARENT mode, passing through");
        return packet;
    }

    uint32_t encryptedSize = packet->GetSize();

    // Serialize for "decryption"
    std::vector<uint8_t> ciphertext(encryptedSize);
    packet->CopyData(ciphertext.data(), encryptedSize);

    // Decrypt via AES-GCM (simulated)
    auto decResult = m_cipher->Decrypt(ciphertext);

    if (!decResult.authenticated)
    {
        NS_LOG_WARN("PQC-PDCP RX: GCM authentication FAILED!");
        return nullptr;
    }

    // Create new packet with decrypted content
    Ptr<Packet> decPacket = Create<Packet>(decResult.plaintext.data(),
                                            static_cast<uint32_t>(decResult.plaintext.size()));

    m_packetsDecrypted++;

    // Fire traces
    m_rxOverheadTrace(encryptedSize, decPacket->GetSize());
    m_decryptLatencyTrace(decResult.decryptTime);

    NS_LOG_DEBUG("PQC-PDCP RX: " << encryptedSize << "B -> " << decPacket->GetSize()
                                  << "B (decrypted)");

    return decPacket;
}

PqcPdcpLayer::Mode
PqcPdcpLayer::GetMode() const
{
    return m_mode;
}

uint32_t
PqcPdcpLayer::GetPerPacketOverhead() const
{
    return (m_mode == ENCRYPTED) ? AesGcmCipher::OVERHEAD : 0;
}

uint64_t
PqcPdcpLayer::GetTotalOverheadBytes() const
{
    return m_totalOverheadBytes;
}

uint64_t
PqcPdcpLayer::GetPacketsProcessed() const
{
    return m_packetsEncrypted + m_packetsDecrypted;
}

} // namespace pqc
} // namespace ns3
