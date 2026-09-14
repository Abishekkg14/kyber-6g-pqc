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

NS_LOG_COMPONENT_DEFINE("SimulatedX25519");
NS_OBJECT_ENSURE_REGISTERED(SimulatedX25519);

TypeId
SimulatedX25519::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::pqc::SimulatedX25519")
            .SetParent<Object>()
            .SetGroupName("PqcSecurity")
            .AddConstructor<SimulatedX25519>()
            .AddAttribute("KeyGenTime",
                          "Simulated X25519 key generation time",
                          TimeValue(MicroSeconds(40)),
                          MakeTimeAccessor(&SimulatedX25519::m_keyGenTime),
                          MakeTimeChecker())
            .AddAttribute("DhTime",
                          "Simulated X25519 DH shared secret computation time",
                          TimeValue(MicroSeconds(50)),
                          MakeTimeAccessor(&SimulatedX25519::m_dhTime),
                          MakeTimeChecker())
            .AddTraceSource("KeyGenLatency",
                            "Time taken for X25519 key generation",
                            MakeTraceSourceAccessor(&SimulatedX25519::m_keyGenTrace),
                            "ns3::Time::TracedCallback")
            .AddTraceSource("DhLatency",
                            "Time taken for X25519 DH computation",
                            MakeTraceSourceAccessor(&SimulatedX25519::m_dhTrace),
                            "ns3::Time::TracedCallback");

    return tid;
}

SimulatedX25519::SimulatedX25519()
{
    m_rng = CreateObject<UniformRandomVariable>();
    m_rng->SetAttribute("Min", DoubleValue(0.0));
    m_rng->SetAttribute("Max", DoubleValue(255.0));
}

SimulatedX25519::~SimulatedX25519()
{
}

std::vector<uint8_t>
SimulatedX25519::GenerateRandomBytes(uint32_t size)
{
    std::vector<uint8_t> bytes(size);
    for (uint32_t i = 0; i < size; ++i)
    {
        bytes[i] = static_cast<uint8_t>(m_rng->GetInteger(0, 255));
    }
    return bytes;
}

SimulatedX25519::KeyPair
SimulatedX25519::KeyGen()
{
    KeyPair kp;
    kp.publicKey = GenerateRandomBytes(PUBLIC_KEY_SIZE);
    kp.secretKey = GenerateRandomBytes(SECRET_KEY_SIZE);
    kp.generationTime = m_keyGenTime;

    NS_LOG_INFO("X25519 KeyGen: pk=32B sk=32B time=" << m_keyGenTime.As(Time::US));
    m_keyGenTrace(m_keyGenTime);

    return kp;
}

SimulatedX25519::SharedSecretResult
SimulatedX25519::ComputeSharedSecret(const std::vector<uint8_t>& mySecretKey,
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
