/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#include "x25519-ecdh.h"

#include "ns3/double.h"
#include "ns3/log.h"
#include "ns3/simulator.h"

namespace ns3
{
namespace pqc
{

NS_LOG_COMPONENT_DEFINE("X25519Ecdh");
NS_OBJECT_ENSURE_REGISTERED(X25519Ecdh);

TypeId
X25519Ecdh::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::pqc::X25519Ecdh")
            .SetParent<Object>()
            .SetGroupName("PqcSecurity")
            .AddConstructor<X25519Ecdh>()
            .AddAttribute("KeyGenTime",
                          "Simulated X25519 key generation time",
                          TimeValue(MicroSeconds(40)),
                          MakeTimeAccessor(&X25519Ecdh::m_keyGenTime),
                          MakeTimeChecker())
            .AddAttribute("DhTime",
                          "Simulated X25519 DH shared secret computation time",
                          TimeValue(MicroSeconds(50)),
                          MakeTimeAccessor(&X25519Ecdh::m_dhTime),
                          MakeTimeChecker())
            .AddTraceSource("KeyGenLatency",
                            "Time taken for X25519 key generation",
                            MakeTraceSourceAccessor(&X25519Ecdh::m_keyGenTrace),
                            "ns3::Time::TracedCallback")
            .AddTraceSource("DhLatency",
                            "Time taken for X25519 DH computation",
                            MakeTraceSourceAccessor(&X25519Ecdh::m_dhTrace),
                            "ns3::Time::TracedCallback");

    return tid;
}

X25519Ecdh::X25519Ecdh()
{
    m_rng = CreateObject<UniformRandomVariable>();
    m_rng->SetAttribute("Min", DoubleValue(0.0));
    m_rng->SetAttribute("Max", DoubleValue(255.0));
}

X25519Ecdh::~X25519Ecdh()
{
}

std::vector<uint8_t>
X25519Ecdh::GenerateRandomBytes(uint32_t size)
{
    std::vector<uint8_t> bytes(size);
    for (uint32_t i = 0; i < size; ++i)
    {
        bytes[i] = static_cast<uint8_t>(m_rng->GetInteger(0, 255));
    }
    return bytes;
}

X25519Ecdh::KeyPair
X25519Ecdh::KeyGen()
{
    KeyPair kp;
    kp.publicKey = GenerateRandomBytes(PUBLIC_KEY_SIZE);
    kp.secretKey = GenerateRandomBytes(SECRET_KEY_SIZE);
    kp.generationTime = m_keyGenTime;

    NS_LOG_INFO("X25519 KeyGen: pk=32B sk=32B time=" << m_keyGenTime.As(Time::US));
    m_keyGenTrace(m_keyGenTime);

    return kp;
}

X25519Ecdh::SharedSecretResult
X25519Ecdh::ComputeSharedSecret(const std::vector<uint8_t>& mySecretKey,
                                 const std::vector<uint8_t>& peerPublicKey)
{
    SharedSecretResult result;
    result.sharedSecret = GenerateRandomBytes(SHARED_SECRET_SIZE);
    result.computeTime = m_dhTime;

    NS_LOG_INFO("X25519 DH: ss=32B time=" << m_dhTime.As(Time::US));
    m_dhTrace(m_dhTime);

    return result;
}

} // namespace pqc
} // namespace ns3
