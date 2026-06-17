/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#include "pqc-rrc-extension.h"

#include "ns3/boolean.h"
#include "ns3/enum.h"
#include "ns3/log.h"
#include "ns3/simulator.h"

namespace ns3
{
namespace pqc
{

NS_LOG_COMPONENT_DEFINE("PqcRrcExtension");
NS_OBJECT_ENSURE_REGISTERED(PqcRrcExtension);

TypeId
PqcRrcExtension::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::pqc::PqcRrcExtension")
            .SetParent<Object>()
            .SetGroupName("PqcSecurity")
            .AddConstructor<PqcRrcExtension>()
            .AddAttribute("Role",
                          "Role of this RRC extension (0=UE, 1=gNB)",
                          EnumValue(UE_ROLE),
                          MakeEnumAccessor<Role>(&PqcRrcExtension::m_role),
                          MakeEnumChecker(UE_ROLE, "UE", GNB_ROLE, "GNB"))
            .AddAttribute("EnableAuthentication",
                          "Enable ML-DSA signature authentication",
                          BooleanValue(true),
                          MakeBooleanAccessor(&PqcRrcExtension::m_enableAuth),
                          MakeBooleanChecker())
            .AddTraceSource("RrcRequestSize",
                            "Total size of PQC RRC Connection Request IE",
                            MakeTraceSourceAccessor(&PqcRrcExtension::m_rrcRequestSizeTrace),
                            "ns3::TracedValueCallback::Uint32")
            .AddTraceSource("RrcSetupSize",
                            "Total size of PQC RRC Connection Setup IE",
                            MakeTraceSourceAccessor(&PqcRrcExtension::m_rrcSetupSizeTrace),
                            "ns3::TracedValueCallback::Uint32")
            .AddTraceSource("HandshakeLatency",
                            "End-to-end PQC handshake latency",
                            MakeTraceSourceAccessor(&PqcRrcExtension::m_handshakeLatencyTrace),
                            "ns3::Time::TracedCallback")
            .AddTraceSource("ProcessingTime",
                            "Total crypto processing time",
                            MakeTraceSourceAccessor(&PqcRrcExtension::m_processingTimeTrace),
                            "ns3::Time::TracedCallback")
            .AddTraceSource("AuthResult",
                            "ML-DSA authentication result (true=success)",
                            MakeTraceSourceAccessor(&PqcRrcExtension::m_authResultTrace),
                            "ns3::TracedCallback::Bool");

    return tid;
}

PqcRrcExtension::PqcRrcExtension()
    : m_role(UE_ROLE),
      m_cryptoMode(CryptoMode::HYBRID_KYBER_ECDH),
      m_enableAuth(true)
{
    m_hybridKem = CreateObject<HybridKemCombiner>();
    m_signer = CreateObject<MlDsaSigner>();
    m_verifier = CreateObject<MlDsaSigner>();
}

PqcRrcExtension::~PqcRrcExtension()
{
}

void
PqcRrcExtension::SetRole(Role role)
{
    m_role = role;
}

void
PqcRrcExtension::SetPdcpLayer(Ptr<PqcPdcpLayer> pdcp)
{
    m_pdcpLayer = pdcp;
}

void
PqcRrcExtension::SetCryptoMode(CryptoMode mode)
{
    m_cryptoMode = mode;
    if (m_hybridKem)
    {
        m_hybridKem->SetCryptoMode(mode);
    }
}

void
PqcRrcExtension::SetKyberLevel(CrystalsKyberKem::SecurityLevel level)
{
    if (m_hybridKem)
    {
        m_hybridKem->SetKyberLevel(level);
    }
}

void
PqcRrcExtension::SetMlDsaLevel(MlDsaSigner::Level level)
{
    if (m_signer)
    {
        m_signer->SetLevel(level);
    }
    if (m_verifier)
    {
        m_verifier->SetLevel(level);
    }
}

void
PqcRrcExtension::SetHardwareProfile(const HardwareProfile& profile)
{
    if (m_hybridKem)
    {
        m_hybridKem->SetHardwareProfile(profile);
    }
}

void
PqcRrcExtension::SetParallelHandshake(bool parallel)
{
    if (m_hybridKem)
    {
        m_hybridKem->SetParallelHandshake(parallel);
    }
}

// ═══════════════════════════════════════════════════════════
// UE-SIDE: Generate RRC Connection Request
// ═══════════════════════════════════════════════════════════

PqcRrcIePayload
PqcRrcExtension::GenerateConnectionRequest()
{
    NS_ASSERT_MSG(m_role == UE_ROLE, "GenerateConnectionRequest called on gNB!");

    m_handshakeStartTime = Simulator::Now();
    PqcRrcIePayload payload;
    Time processingTime = Seconds(0);

    NS_LOG_INFO("╔══ PQC RRC Connection Request (UE) ══╗");

    // 1. Generate hybrid key pair (ECDH + Kyber)
    m_localKeys = m_hybridKem->GenerateKeyPair();
    payload.kyberPublicKey = m_localKeys.kyberKeys.publicKey;
    payload.ecdhPublicKey = m_localKeys.ecdhKeys.publicKey;
    processingTime += m_localKeys.totalGenerationTime;

    NS_LOG_INFO("  Kyber PK: " << payload.kyberPublicKey.size() << " bytes");
    NS_LOG_INFO("  ECDH PK:  " << payload.ecdhPublicKey.size() << " bytes");

    // 2. Sign with ML-DSA (if authentication enabled)
    if (m_enableAuth)
    {
        auto dataToSign = payload.kyberPublicKey;
        dataToSign.insert(dataToSign.end(),
                          payload.ecdhPublicKey.begin(),
                          payload.ecdhPublicKey.end());

        auto sig = m_signer->Sign(dataToSign);
        payload.mlDsaSignature = sig.sigBytes;
        payload.mlDsaCertificate = m_signer->GetPublicKey();
        processingTime += sig.signTime;

        NS_LOG_INFO("  ML-DSA Sig: " << payload.mlDsaSignature.size() << " bytes");
        NS_LOG_INFO("  ML-DSA Cert: " << payload.mlDsaCertificate.size() << " bytes");
    }

    payload.processingDelay = processingTime;
    m_totalProcessingTime = processingTime;
    m_bytesSent = payload.TotalSize();

    NS_LOG_INFO("  Total IE size: " << payload.TotalSize() << " bytes");
    NS_LOG_INFO("  Processing time: " << processingTime.As(Time::US));
    NS_LOG_INFO("╚══════════════════════════════════════╝");

    m_rrcRequestSizeTrace(payload.TotalSize());
    m_processingTimeTrace(processingTime);

    return payload;
}

// ═══════════════════════════════════════════════════════════
// gNB-SIDE: Process UE's request and generate response
// ═══════════════════════════════════════════════════════════

PqcRrcIePayload
PqcRrcExtension::ProcessConnectionRequest(const PqcRrcIePayload& uePayload)
{
    NS_ASSERT_MSG(m_role == GNB_ROLE, "ProcessConnectionRequest called on UE!");

    PqcRrcIePayload response;
    Time processingTime = Seconds(0);

    NS_LOG_INFO("╔══ PQC RRC Connection Setup (gNB) ══╗");
    NS_LOG_INFO("  Received UE payload: " << uePayload.TotalSize() << " bytes");

    // 1. Verify ML-DSA signature (if authentication enabled)
    if (m_enableAuth && !uePayload.mlDsaSignature.empty())
    {
        auto dataToVerify = uePayload.kyberPublicKey;
        dataToVerify.insert(dataToVerify.end(),
                            uePayload.ecdhPublicKey.begin(),
                            uePayload.ecdhPublicKey.end());

        MlDsaSigner::Signature sig;
        sig.sigBytes = uePayload.mlDsaSignature;

        auto verifyResult = m_verifier->Verify(dataToVerify, sig, uePayload.mlDsaCertificate);
        processingTime += verifyResult.verifyTime;

        m_authResultTrace(verifyResult.valid);

        if (!verifyResult.valid)
        {
            NS_LOG_WARN("  ✗ ML-DSA AUTHENTICATION FAILED — rejecting UE");
            return PqcRrcIePayload::Rejected();
        }
        NS_LOG_INFO("  ✓ ML-DSA authentication PASSED");
    }

    // 2. Perform hybrid encapsulation toward UE's public keys
    auto hybridResult = m_hybridKem->Encapsulate(
        uePayload.ecdhPublicKey,
        uePayload.kyberPublicKey);
    processingTime += hybridResult.totalTime;

    response.kyberCiphertext = hybridResult.kyberCiphertext;
    response.ecdhPublicKey = hybridResult.ecdhPublicKey;

    NS_LOG_INFO("  Kyber CT: " << response.kyberCiphertext.size() << " bytes");
    NS_LOG_INFO("  ECDH PK:  " << response.ecdhPublicKey.size() << " bytes");

    // 3. Sign the response with gNB's ML-DSA key
    if (m_enableAuth)
    {
        auto dataToSign = response.kyberCiphertext;
        dataToSign.insert(dataToSign.end(),
                          response.ecdhPublicKey.begin(),
                          response.ecdhPublicKey.end());

        auto sig = m_signer->Sign(dataToSign);
        response.mlDsaSignature = sig.sigBytes;
        processingTime += sig.signTime;

        NS_LOG_INFO("  gNB ML-DSA Sig: " << response.mlDsaSignature.size() << " bytes");
    }

    // 4. Derive and install session keys
    m_sessionKeys = m_hybridKem->DeriveSessionKeys(hybridResult.combinedSecret);
    m_handshakeComplete = true;

    if (m_pdcpLayer)
    {
        m_pdcpLayer->InstallSessionKeys(m_sessionKeys);
    }

    response.processingDelay = processingTime;
    m_totalProcessingTime = processingTime;
    m_bytesSent = response.TotalSize();

    NS_LOG_INFO("  Total response IE: " << response.TotalSize() << " bytes");
    NS_LOG_INFO("  Processing time: " << processingTime.As(Time::US));
    NS_LOG_INFO("╚═════════════════════════════════════╝");

    m_rrcSetupSizeTrace(response.TotalSize());
    m_processingTimeTrace(processingTime);

    return response;
}

// ═══════════════════════════════════════════════════════════
// UE-SIDE: Complete the key exchange
// ═══════════════════════════════════════════════════════════

PqcSessionKeys
PqcRrcExtension::CompleteKeyExchange(const PqcRrcIePayload& gnbResponse)
{
    NS_ASSERT_MSG(m_role == UE_ROLE, "CompleteKeyExchange called on gNB!");

    Time processingTime = Seconds(0);

    NS_LOG_INFO("╔══ PQC Key Exchange Complete (UE) ══╗");

    // 1. Verify gNB's ML-DSA signature
    if (m_enableAuth && !gnbResponse.mlDsaSignature.empty())
    {
        auto dataToVerify = gnbResponse.kyberCiphertext;
        dataToVerify.insert(dataToVerify.end(),
                            gnbResponse.ecdhPublicKey.begin(),
                            gnbResponse.ecdhPublicKey.end());

        MlDsaSigner::Signature sig;
        sig.sigBytes = gnbResponse.mlDsaSignature;

        // In real implementation, would use gNB's cert from AMF
        auto verifyResult = m_verifier->Verify(dataToVerify, sig, gnbResponse.mlDsaCertificate);
        processingTime += verifyResult.verifyTime;

        m_authResultTrace(verifyResult.valid);
        NS_LOG_INFO("  gNB auth: " << (verifyResult.valid ? "PASSED" : "FAILED"));
    }

    // 2. Decapsulate hybrid KEM
    auto combinedSecret = m_hybridKem->Decapsulate(
        m_localKeys,
        gnbResponse.ecdhPublicKey,
        gnbResponse.kyberCiphertext);

    // 3. Derive session keys
    m_sessionKeys = m_hybridKem->DeriveSessionKeys(combinedSecret);
    m_handshakeComplete = true;

    // 4. Install in PDCP layer
    if (m_pdcpLayer)
    {
        m_pdcpLayer->InstallSessionKeys(m_sessionKeys);
    }

    // Calculate total handshake latency
    Time handshakeLatency = Simulator::Now() - m_handshakeStartTime +
                            processingTime + gnbResponse.processingDelay;

    NS_LOG_INFO("  Session keys established!");
    NS_LOG_INFO("  Key is hybrid: " << m_sessionKeys.isHybrid);
    NS_LOG_INFO("  Handshake latency: " << handshakeLatency.As(Time::US));
    NS_LOG_INFO("╚═════════════════════════════════════╝");

    m_handshakeLatencyTrace(handshakeLatency);

    return m_sessionKeys;
}

PqcSessionKeys
PqcRrcExtension::GetSessionKeys() const
{
    return m_sessionKeys;
}

bool
PqcRrcExtension::IsHandshakeComplete() const
{
    return m_handshakeComplete;
}

uint32_t
PqcRrcExtension::GetHandshakeBytesSent() const
{
    return m_bytesSent;
}

Time
PqcRrcExtension::GetHandshakeProcessingTime() const
{
    return m_totalProcessingTime;
}

} // namespace pqc
} // namespace ns3
