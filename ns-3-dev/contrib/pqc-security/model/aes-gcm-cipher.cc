/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#include "aes-gcm-cipher.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

namespace ns3
{
namespace pqc
{

NS_LOG_COMPONENT_DEFINE("AesGcmCipher");
NS_OBJECT_ENSURE_REGISTERED(AesGcmCipher);

TypeId
AesGcmCipher::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::pqc::AesGcmCipher")
            .SetParent<Object>()
            .SetGroupName("PqcSecurity")
            .AddConstructor<AesGcmCipher>()
            .AddAttribute("EncryptTimePerByte",
                          "Simulated AES-GCM encryption time per byte",
                          TimeValue(NanoSeconds(1)),
                          MakeTimeAccessor(&AesGcmCipher::m_encryptTimePerByte),
                          MakeTimeChecker())
            .AddAttribute("DecryptTimePerByte",
                          "Simulated AES-GCM decryption time per byte",
                          TimeValue(NanoSeconds(1)),
                          MakeTimeAccessor(&AesGcmCipher::m_decryptTimePerByte),
                          MakeTimeChecker())
            .AddAttribute("EncryptFixedOverhead",
                          "Fixed per-packet encryption setup time",
                          TimeValue(MicroSeconds(1)),
                          MakeTimeAccessor(&AesGcmCipher::m_encryptFixedOverhead),
                          MakeTimeChecker())
            .AddAttribute("DecryptFixedOverhead",
                          "Fixed per-packet decryption setup time",
                          TimeValue(MicroSeconds(1)),
                          MakeTimeAccessor(&AesGcmCipher::m_decryptFixedOverhead),
                          MakeTimeChecker())
            .AddTraceSource("EncryptLatency",
                            "Per-packet AES-GCM encryption time",
                            MakeTraceSourceAccessor(&AesGcmCipher::m_encryptTrace),
                            "ns3::Time::TracedCallback")
            .AddTraceSource("DecryptLatency",
                            "Per-packet AES-GCM decryption time",
                            MakeTraceSourceAccessor(&AesGcmCipher::m_decryptTrace),
                            "ns3::Time::TracedCallback")
            .AddTraceSource("OverheadBytes",
                            "Plaintext vs encrypted sizes",
                            MakeTraceSourceAccessor(&AesGcmCipher::m_overheadTrace),
                            "ns3::TracedCallback::Uint32Uint32");

    return tid;
}

AesGcmCipher::AesGcmCipher()
{
}

AesGcmCipher::~AesGcmCipher()
{
}

void
AesGcmCipher::InstallKeys(const PqcSessionKeys& keys)
{
    m_keys = keys;
    m_keysInstalled = true;
    NS_LOG_INFO("AES-GCM: Session keys installed at t=" << Simulator::Now().As(Time::MS));
}

bool
AesGcmCipher::HasKeys() const
{
    return m_keysInstalled;
}

AesGcmCipher::EncryptResult
AesGcmCipher::Encrypt(const std::vector<uint8_t>& plaintext)
{
    EncryptResult result;

    if (!m_keysInstalled)
    {
        NS_LOG_WARN("AES-GCM Encrypt: No keys installed! Passing through unencrypted.");
        result.ciphertext = plaintext;
        result.encryptTime = Seconds(0);
        result.overhead = 0;
        return result;
    }

    // Simulated encryption: prepend nonce (12B), copy plaintext, append tag (16B)
    auto nonce = m_keys.NextNonce();

    result.ciphertext.reserve(NONCE_SIZE + plaintext.size() + TAG_SIZE);

    // Prepend nonce
    result.ciphertext.insert(result.ciphertext.end(), nonce.begin(), nonce.end());

    // "Encrypted" plaintext (in simulation, we keep it readable)
    result.ciphertext.insert(result.ciphertext.end(), plaintext.begin(), plaintext.end());

    // Append simulated GCM tag (16 bytes of 0xAA — stands in for real GHASH output)
    result.ciphertext.insert(result.ciphertext.end(), TAG_SIZE, 0xAA);

    // Compute timing
    result.encryptTime =
        m_encryptFixedOverhead + m_encryptTimePerByte * plaintext.size();
    result.overhead = OVERHEAD;

    m_encryptTrace(result.encryptTime);
    m_overheadTrace(static_cast<uint32_t>(plaintext.size()),
                    static_cast<uint32_t>(result.ciphertext.size()));

    return result;
}

AesGcmCipher::DecryptResult
AesGcmCipher::Decrypt(const std::vector<uint8_t>& ciphertext)
{
    DecryptResult result;

    if (!m_keysInstalled)
    {
        NS_LOG_WARN("AES-GCM Decrypt: No keys installed!");
        result.plaintext = ciphertext;
        result.authenticated = false;
        result.decryptTime = Seconds(0);
        return result;
    }

    if (ciphertext.size() < OVERHEAD)
    {
        NS_LOG_WARN("AES-GCM Decrypt: Ciphertext too small ("
                     << ciphertext.size() << " < " << OVERHEAD << " bytes)");
        result.authenticated = false;
        result.decryptTime = Seconds(0);
        return result;
    }

    // Strip nonce (first 12 bytes) and tag (last 16 bytes)
    uint32_t plaintextSize = static_cast<uint32_t>(ciphertext.size()) - OVERHEAD;
    result.plaintext.assign(ciphertext.begin() + NONCE_SIZE,
                            ciphertext.begin() + NONCE_SIZE + plaintextSize);

    // In simulation, authentication always succeeds
    result.authenticated = true;

    // Compute timing
    result.decryptTime = m_decryptFixedOverhead + m_decryptTimePerByte * plaintextSize;

    m_decryptTrace(result.decryptTime);

    return result;
}

} // namespace pqc
} // namespace ns3
