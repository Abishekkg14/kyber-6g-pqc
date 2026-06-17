/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#include "crystals-kyber-kem.h"

#include "ns3/double.h"
#include "ns3/enum.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/uinteger.h"

namespace ns3
{
namespace pqc
{

NS_LOG_COMPONENT_DEFINE("CrystalsKyberKem");
NS_OBJECT_ENSURE_REGISTERED(CrystalsKyberKem);

// ── FIPS 203 Table 1: Kyber parameter sets ──
const std::map<CrystalsKyberKem::SecurityLevel, CrystalsKyberKem::Sizes>
    CrystalsKyberKem::SIZE_TABLE = {
        {KYBER_512, {800, 1632, 768, 32}},
        {KYBER_768, {1184, 2400, 1088, 32}},
        {KYBER_1024, {1568, 3168, 1568, 32}},
};

TypeId
CrystalsKyberKem::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::pqc::CrystalsKyberKem")
            .SetParent<Object>()
            .SetGroupName("PqcSecurity")
            .AddConstructor<CrystalsKyberKem>()
            .AddAttribute("SecurityLevel",
                          "Kyber security level (0=512, 1=768, 2=1024)",
                          EnumValue(KYBER_768),
                          MakeEnumAccessor<SecurityLevel>(&CrystalsKyberKem::m_level),
                          MakeEnumChecker(KYBER_512,
                                          "KYBER_512",
                                          KYBER_768,
                                          "KYBER_768",
                                          KYBER_1024,
                                          "KYBER_1024"))
            .AddAttribute(
                "KeyGenTime",
                "Simulated key generation time (ARM Cortex-A72 benchmark)",
                TimeValue(MicroSeconds(150)),
                MakeTimeAccessor(&CrystalsKyberKem::m_keyGenTime),
                MakeTimeChecker())
            .AddAttribute(
                "EncapsTime",
                "Simulated encapsulation time",
                TimeValue(MicroSeconds(180)),
                MakeTimeAccessor(&CrystalsKyberKem::m_encapsTime),
                MakeTimeChecker())
            .AddAttribute(
                "DecapsTime",
                "Simulated decapsulation time",
                TimeValue(MicroSeconds(190)),
                MakeTimeAccessor(&CrystalsKyberKem::m_decapsTime),
                MakeTimeChecker())
            .AddTraceSource("KeyGenLatency",
                            "Time taken for Kyber key generation",
                            MakeTraceSourceAccessor(&CrystalsKyberKem::m_keyGenTrace),
                            "ns3::Time::TracedCallback")
            .AddTraceSource("EncapsLatency",
                            "Time taken for Kyber encapsulation",
                            MakeTraceSourceAccessor(&CrystalsKyberKem::m_encapsTrace),
                            "ns3::Time::TracedCallback")
            .AddTraceSource("DecapsLatency",
                            "Time taken for Kyber decapsulation",
                            MakeTraceSourceAccessor(&CrystalsKyberKem::m_decapsTrace),
                            "ns3::Time::TracedCallback")
            .AddTraceSource("PublicKeySize",
                            "Size of generated Kyber public key in bytes",
                            MakeTraceSourceAccessor(&CrystalsKyberKem::m_publicKeySizeTrace),
                            "ns3::TracedValueCallback::Uint32")
            .AddTraceSource("CiphertextSize",
                            "Size of Kyber ciphertext in bytes",
                            MakeTraceSourceAccessor(&CrystalsKyberKem::m_ciphertextSizeTrace),
                            "ns3::TracedValueCallback::Uint32")
            .AddTraceSource("CryptoEnergy",
                            "Simulated Energy consumed by computation in microjoules",
                            MakeTraceSourceAccessor(&CrystalsKyberKem::m_energyTrace),
                            "ns3::TracedValueCallback::Double")
            .AddTraceSource("CryptoMemory",
                            "Simulated peak memory footprint by computation in bytes",
                            MakeTraceSourceAccessor(&CrystalsKyberKem::m_memoryTrace),
                            "ns3::TracedValueCallback::Uint32");

    return tid;
}

CrystalsKyberKem::CrystalsKyberKem()
    : m_level(KYBER_768)
{
    m_rng = CreateObject<UniformRandomVariable>();
    m_rng->SetAttribute("Min", DoubleValue(0.0));
    m_rng->SetAttribute("Max", DoubleValue(255.0));
}

CrystalsKyberKem::~CrystalsKyberKem()
{
}

std::vector<uint8_t>
CrystalsKyberKem::GenerateRandomBytes(uint32_t size)
{
    std::vector<uint8_t> bytes(size);
    for (uint32_t i = 0; i < size; ++i)
    {
        bytes[i] = static_cast<uint8_t>(m_rng->GetInteger(0, 255));
    }
    return bytes;
}

CrystalsKyberKem::Sizes
CrystalsKyberKem::GetSizes() const
{
    return SIZE_TABLE.at(m_level);
}

CrystalsKyberKem::SecurityLevel
CrystalsKyberKem::GetLevel() const
{
    return m_level;
}

void
CrystalsKyberKem::SetSecurityLevel(SecurityLevel level)
{
    m_level = level;
}

CrystalsKyberKem::EnergyMetrics
CrystalsKyberKem::GetEnergyMetrics() const
{
    // High-fidelity approximations based on standard Cortex-M4 / A72 LWE processing benchmarks
    if (m_level == KYBER_512) return { 1.2, 1.5, 1.6 }; // CPU active current * time
    if (m_level == KYBER_768) return { 2.1, 2.5, 2.7 };
    return { 3.5, 4.0, 4.2 }; // KYBER_1024
}

CrystalsKyberKem::KeyPair
CrystalsKyberKem::KeyGen()
{
    auto sizes = GetSizes();
    KeyPair kp;

    NS_LOG_INFO("Kyber KeyGen: level=" << m_level << " pk_size=" << sizes.publicKeySize
                                       << " sk_size=" << sizes.secretKeySize);

    kp.publicKey = GenerateRandomBytes(sizes.publicKeySize);
    kp.secretKey = GenerateRandomBytes(sizes.secretKeySize);
    kp.generationTime = m_keyGenTime;

    m_keyGenTrace(m_keyGenTime);
    m_publicKeySizeTrace(sizes.publicKeySize);

    // Approximate memory: PK + SK + internal polynomial arrays
    uint32_t memRequired = sizes.publicKeySize + sizes.secretKeySize + 4096;
    m_memoryTrace(memRequired);
    m_energyTrace(GetEnergyMetrics().keyGenEnergy);

    return kp;
}

CrystalsKyberKem::EncapsResult
CrystalsKyberKem::Encapsulate(const std::vector<uint8_t>& publicKey)
{
    auto sizes = GetSizes();
    EncapsResult result;

    NS_LOG_INFO("Kyber Encaps: ct_size=" << sizes.ciphertextSize
                                         << " ss_size=" << sizes.sharedSecretSize);

    // Validate public key size
    if (publicKey.size() != sizes.publicKeySize)
    {
        NS_LOG_WARN("Kyber Encaps: public key size mismatch! Expected "
                     << sizes.publicKeySize << " got " << publicKey.size());
    }

    result.ciphertext = GenerateRandomBytes(sizes.ciphertextSize);
    result.sharedSecret = GenerateRandomBytes(sizes.sharedSecretSize);
    result.encapsulationTime = m_encapsTime;

    m_encapsTrace(m_encapsTime);
    m_ciphertextSizeTrace(sizes.ciphertextSize);

    uint32_t memRequired = sizes.publicKeySize + sizes.ciphertextSize + sizes.sharedSecretSize + 4096;
    m_memoryTrace(memRequired);
    m_energyTrace(GetEnergyMetrics().encapsEnergy);

    return result;
}

CrystalsKyberKem::DecapsResult
CrystalsKyberKem::Decapsulate(const std::vector<uint8_t>& secretKey,
                               const std::vector<uint8_t>& ciphertext)
{
    auto sizes = GetSizes();
    DecapsResult result;

    NS_LOG_INFO("Kyber Decaps: ss_size=" << sizes.sharedSecretSize);

    if (secretKey.size() != sizes.secretKeySize)
    {
        NS_LOG_WARN("Kyber Decaps: secret key size mismatch!");
    }
    if (ciphertext.size() != sizes.ciphertextSize)
    {
        NS_LOG_WARN("Kyber Decaps: ciphertext size mismatch!");
    }

    // In simulation, shared secret is deterministic from the encapsulation
    // (both sides derive the same random bytes in a real KEM).
    // We generate a fresh random value here; in the simulation framework,
    // the HybridKemCombiner coordinates to ensure both sides get identical keys.
    result.sharedSecret = GenerateRandomBytes(sizes.sharedSecretSize);
    result.decapsulationTime = m_decapsTime;

    m_decapsTrace(m_decapsTime);

    uint32_t memRequired = sizes.secretKeySize + sizes.ciphertextSize + sizes.sharedSecretSize + 4096;
    m_memoryTrace(memRequired);
    m_energyTrace(GetEnergyMetrics().decapsEnergy);

    return result;
}

} // namespace pqc
} // namespace ns3
