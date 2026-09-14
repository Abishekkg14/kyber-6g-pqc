/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#include "ml-dsa-signer.h"

#include "ns3/double.h"
#include "ns3/enum.h"
#include "ns3/log.h"
#include "ns3/simulator.h"

namespace ns3
{
namespace pqc
{

NS_LOG_COMPONENT_DEFINE("SimulatedMlDsa");
NS_OBJECT_ENSURE_REGISTERED(SimulatedMlDsa);

// FIPS 204 Table 1: ML-DSA parameter sets
const std::map<SimulatedMlDsa::Level, SimulatedMlDsa::Sizes> SimulatedMlDsa::SIZE_TABLE = {
    {ML_DSA_44, {1312, 2560, 2420}},
    {ML_DSA_65, {1952, 4032, 3309}},
    {ML_DSA_87, {2592, 4896, 4627}},
};

TypeId
SimulatedMlDsa::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::pqc::SimulatedMlDsa")
            .SetParent<Object>()
            .SetGroupName("PqcSecurity")
            .AddConstructor<SimulatedMlDsa>()
            .AddAttribute("Level",
                          "ML-DSA security level (0=ML-DSA-44, 1=ML-DSA-65, 2=ML-DSA-87)",
                          EnumValue(ML_DSA_65),
                          MakeEnumAccessor<Level>(&SimulatedMlDsa::m_level),
                          MakeEnumChecker(ML_DSA_44,
                                          "ML_DSA_44",
                                          ML_DSA_65,
                                          "ML_DSA_65",
                                          ML_DSA_87,
                                          "ML_DSA_87"))
            .AddAttribute("KeyGenTime",
                          "Simulated ML-DSA key generation time",
                          TimeValue(MicroSeconds(300)),
                          MakeTimeAccessor(&SimulatedMlDsa::m_keyGenTime),
                          MakeTimeChecker())
            .AddAttribute("SignTime",
                          "Simulated ML-DSA signing time (ARM Cortex-A72)",
                          TimeValue(MicroSeconds(500)),
                          MakeTimeAccessor(&SimulatedMlDsa::m_signTime),
                          MakeTimeChecker())
            .AddAttribute("VerifyTime",
                          "Simulated ML-DSA verification time",
                          TimeValue(MicroSeconds(200)),
                          MakeTimeAccessor(&SimulatedMlDsa::m_verifyTime),
                          MakeTimeChecker())
            .AddTraceSource("SignLatency",
                            "Time taken for ML-DSA signing",
                            MakeTraceSourceAccessor(&SimulatedMlDsa::m_signTrace),
                            "ns3::Time::TracedCallback")
            .AddTraceSource("VerifyLatency",
                            "Time taken for ML-DSA verification",
                            MakeTraceSourceAccessor(&SimulatedMlDsa::m_verifyTrace),
                            "ns3::Time::TracedCallback")
            .AddTraceSource("SignatureSize",
                            "ML-DSA signature size in bytes",
                            MakeTraceSourceAccessor(&SimulatedMlDsa::m_signatureSizeTrace),
                            "ns3::TracedValueCallback::Uint32")
            .AddTraceSource("PublicKeySize",
                            "ML-DSA public key (certificate) size in bytes",
                            MakeTraceSourceAccessor(&SimulatedMlDsa::m_publicKeySizeTrace),
                            "ns3::TracedValueCallback::Uint32");

    return tid;
}

SimulatedMlDsa::SimulatedMlDsa()
    : m_level(ML_DSA_65)
{
    m_rng = CreateObject<UniformRandomVariable>();
    m_rng->SetAttribute("Min", DoubleValue(0.0));
    m_rng->SetAttribute("Max", DoubleValue(255.0));
}

SimulatedMlDsa::~SimulatedMlDsa()
{
}

std::vector<uint8_t>
SimulatedMlDsa::GenerateRandomBytes(uint32_t size)
{
    std::vector<uint8_t> bytes(size);
    for (uint32_t i = 0; i < size; ++i)
    {
        bytes[i] = static_cast<uint8_t>(m_rng->GetInteger(0, 255));
    }
    return bytes;
}

SimulatedMlDsa::Sizes
SimulatedMlDsa::GetSizes() const
{
    return SIZE_TABLE.at(m_level);
}

void
SimulatedMlDsa::SetLevel(Level level)
{
    m_level = level;
    m_keysGenerated = false;
}

SimulatedMlDsa::KeyPair
SimulatedMlDsa::KeyGen()
{
    auto sizes = GetSizes();
    KeyPair kp;

    kp.publicKey = GenerateRandomBytes(sizes.publicKeySize);
    kp.secretKey = GenerateRandomBytes(sizes.secretKeySize);
    kp.generationTime = m_keyGenTime;

    NS_LOG_INFO("ML-DSA KeyGen: level=" << m_level << " pk=" << sizes.publicKeySize
                                        << "B sk=" << sizes.secretKeySize << "B");

    m_publicKeySizeTrace(sizes.publicKeySize);
    return kp;
}

SimulatedMlDsa::Signature
SimulatedMlDsa::Sign(const std::vector<uint8_t>& message)
{
    // Ensure we have identity keys
    if (!m_keysGenerated)
    {
        m_identityKeys = KeyGen();
        m_keysGenerated = true;
    }

    auto sizes = GetSizes();
    Signature sig;

    sig.sigBytes = GenerateRandomBytes(sizes.signatureSize);
    sig.signTime = m_signTime;

    NS_LOG_INFO("ML-DSA Sign: msg=" << message.size() << "B sig=" << sizes.signatureSize
                                    << "B time=" << m_signTime.As(Time::US));

    m_signTrace(m_signTime);
    m_signatureSizeTrace(sizes.signatureSize);

    return sig;
}

SimulatedMlDsa::VerifyResult
SimulatedMlDsa::Verify(const std::vector<uint8_t>& message,
                     const Signature& sig,
                     const std::vector<uint8_t>& publicKey)
{
    auto sizes = GetSizes();
    VerifyResult result;

    // Check that the signature is the correct size
    if (sig.sigBytes.size() != sizes.signatureSize)
    {
        NS_LOG_WARN("ML-DSA Verify: signature size mismatch! Expected "
                     << sizes.signatureSize << " got " << sig.sigBytes.size());
        result.valid = false;
        result.verifyTime = m_verifyTime;
        return result;
    }

    // In simulation, all properly-formed signatures are valid
    // (we simulate a correct implementation, not an attacker)
    result.valid = true;
    result.verifyTime = m_verifyTime;

    NS_LOG_INFO("ML-DSA Verify: VALID msg=" << message.size() << "B time="
                                            << m_verifyTime.As(Time::US));
    m_verifyTrace(m_verifyTime);

    return result;
}

std::vector<uint8_t>
SimulatedMlDsa::GetPublicKey() const
{
    if (m_keysGenerated)
    {
        return m_identityKeys.publicKey;
    }

    // Return an empty vector if keys haven't been generated yet
    NS_LOG_WARN("ML-DSA GetPublicKey called before KeyGen");
    return {};
}

} // namespace pqc
} // namespace ns3
