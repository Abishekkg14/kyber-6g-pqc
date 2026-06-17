/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#include "hybrid-kem-combiner.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <sstream>

namespace ns3
{
namespace pqc
{

NS_LOG_COMPONENT_DEFINE("HybridKemCombiner");
NS_OBJECT_ENSURE_REGISTERED(HybridKemCombiner);

std::map<std::string, std::vector<uint8_t>> HybridKemCombiner::s_encapsSecretCache;

TypeId
HybridKemCombiner::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::pqc::HybridKemCombiner")
            .SetParent<Object>()
            .SetGroupName("PqcSecurity")
            .AddConstructor<HybridKemCombiner>()
            .AddTraceSource("HybridKeyGenLatency",
                            "Total time for hybrid (ECDH+Kyber) key generation",
                            MakeTraceSourceAccessor(&HybridKemCombiner::m_hybridKeyGenTrace),
                            "ns3::Time::TracedCallback")
            .AddTraceSource("HybridEncapsLatency",
                            "Total time for hybrid encapsulation",
                            MakeTraceSourceAccessor(&HybridKemCombiner::m_hybridEncapsTrace),
                            "ns3::Time::TracedCallback")
            .AddTraceSource("HybridDecapsLatency",
                            "Total time for hybrid decapsulation",
                            MakeTraceSourceAccessor(&HybridKemCombiner::m_hybridDecapsTrace),
                            "ns3::Time::TracedCallback")
            .AddTraceSource("TotalPublicKeySize",
                            "Combined ECDH+Kyber public key size in bytes",
                            MakeTraceSourceAccessor(&HybridKemCombiner::m_totalPublicKeySizeTrace),
                            "ns3::TracedValueCallback::Uint32")
            .AddTraceSource(
                "TotalEncapsSize",
                "Combined ECDH pub + Kyber ciphertext size in bytes",
                MakeTraceSourceAccessor(&HybridKemCombiner::m_totalEncapsSizeTrace),
                "ns3::TracedValueCallback::Uint32");

    return tid;
}

HybridKemCombiner::HybridKemCombiner()
    : m_cryptoMode(CryptoMode::HYBRID_KYBER_ECDH),
      m_hwProfile(GetHardwareProfile(HardwareProfileId::JETSON_NANO))
{
    m_ecdh = CreateObject<X25519Ecdh>();
    m_kyber = CreateObject<CrystalsKyberKem>();
}

HybridKemCombiner::~HybridKemCombiner()
{
}

void
HybridKemCombiner::SetCryptoMode(CryptoMode mode)
{
    m_cryptoMode = mode;
}

void
HybridKemCombiner::SetKyberLevel(CrystalsKyberKem::SecurityLevel level)
{
    m_kyber->SetSecurityLevel(level);
}

void
HybridKemCombiner::SetHardwareProfile(const HardwareProfile& profile)
{
    m_hwProfile = profile;
    double scale = profile.cryptoTimingScale;
    m_ecdh->SetAttribute("KeyGenTime", TimeValue(MicroSeconds(40 * scale)));
    m_ecdh->SetAttribute("DhTime", TimeValue(MicroSeconds(50 * scale)));
    m_kyber->SetAttribute("KeyGenTime", TimeValue(MicroSeconds(150 * scale)));
    m_kyber->SetAttribute("EncapsTime", TimeValue(MicroSeconds(180 * scale)));
    m_kyber->SetAttribute("DecapsTime", TimeValue(MicroSeconds(190 * scale)));
}

void
HybridKemCombiner::SetParallelHandshake(bool parallel)
{
    m_parallelHandshake = parallel;
}

Time
HybridKemCombiner::ScaleTime(Time t) const
{
    return MicroSeconds(t.GetMicroSeconds() * m_hwProfile.cryptoTimingScale);
}

Time
HybridKemCombiner::CombineParallelTime(Time a, Time b) const
{
    if (m_parallelHandshake && m_hwProfile.maxParallelOps >= 2)
    {
        // Parallel: max component + 10% memory contention (MODELED)
        double maxUs = std::max(a.GetMicroSeconds(), b.GetMicroSeconds());
        return MicroSeconds(maxUs * 1.1);
    }
    return MicroSeconds(a.GetMicroSeconds() + b.GetMicroSeconds());
}

std::string
HybridKemCombiner::SecretCacheKey(const std::vector<uint8_t>& kyberCt)
{
    std::ostringstream oss;
    for (uint8_t b : kyberCt)
    {
        oss << std::hex << static_cast<int>(b);
    }
    return oss.str();
}

std::vector<uint8_t>
HybridKemCombiner::SimulatedHkdf(const std::vector<uint8_t>& ecdhSs,
                                  const std::vector<uint8_t>& kyberSs)
{
    // Deterministic simulated HKDF-SHA256(ecdhSs || kyberSs, "Kyber6G-HybridKEM-v1")
    static const char salt[] = "Kyber6G-HybridKEM-v1";
    std::vector<uint8_t> input;
    input.reserve(ecdhSs.size() + kyberSs.size() + sizeof(salt));
    input.insert(input.end(), ecdhSs.begin(), ecdhSs.end());
    input.insert(input.end(), kyberSs.begin(), kyberSs.end());
    input.insert(input.end(), salt, salt + sizeof(salt) - 1);

    std::vector<uint8_t> combined(32);
    uint64_t h = 0xcbf29ce484222325ULL;
    for (uint8_t b : input)
    {
        h ^= b;
        h *= 0x100000001b3ULL;
    }
    for (uint32_t i = 0; i < 32; ++i)
    {
        h ^= static_cast<uint64_t>(i);
        h *= 0x100000001b3ULL;
        combined[i] = static_cast<uint8_t>((h >> ((i % 8) * 8)) & 0xFF);
    }
    return combined;
}

HybridKemCombiner::HybridKeyPair
HybridKemCombiner::GenerateKeyPair()
{
    HybridKeyPair hkp;
    hkp.totalGenerationTime = Seconds(0);
    Time ecdhTime = Seconds(0);
    Time kyberTime = Seconds(0);

    if (m_cryptoMode == CryptoMode::ECC_ONLY || m_cryptoMode == CryptoMode::HYBRID_KYBER_ECDH)
    {
        hkp.ecdhKeys = m_ecdh->KeyGen();
        ecdhTime = ScaleTime(hkp.ecdhKeys.generationTime);
    }

    if (m_cryptoMode == CryptoMode::KYBER_ONLY || m_cryptoMode == CryptoMode::KYBER_CACHED ||
        m_cryptoMode == CryptoMode::HYBRID_KYBER_ECDH)
    {
        hkp.kyberKeys = m_kyber->KeyGen();
        kyberTime = ScaleTime(hkp.kyberKeys.generationTime);
    }

    if (m_cryptoMode == CryptoMode::HYBRID_KYBER_ECDH)
    {
        hkp.totalGenerationTime = CombineParallelTime(ecdhTime, kyberTime);
    }
    else
    {
        hkp.totalGenerationTime = MicroSeconds(ecdhTime.GetMicroSeconds() + kyberTime.GetMicroSeconds());
    }

    m_hybridKeyGenTrace(hkp.totalGenerationTime);
    m_totalPublicKeySizeTrace(hkp.TotalPublicKeySize());
    return hkp;
}

HybridKemCombiner::HybridEncapsResult
HybridKemCombiner::Encapsulate(const std::vector<uint8_t>& initiatorEcdhPk,
                                const std::vector<uint8_t>& initiatorKyberPk)
{
    HybridEncapsResult result;
    result.totalTime = Seconds(0);
    std::vector<uint8_t> ecdhSecret;
    std::vector<uint8_t> kyberSecret;
    Time ecdhTime = Seconds(0);
    Time kyberTime = Seconds(0);

    if (m_cryptoMode == CryptoMode::ECC_ONLY || m_cryptoMode == CryptoMode::HYBRID_KYBER_ECDH)
    {
        auto ecdhKp = m_ecdh->KeyGen();
        auto ecdhSs = m_ecdh->ComputeSharedSecret(ecdhKp.secretKey, initiatorEcdhPk);
        result.ecdhPublicKey = ecdhKp.publicKey;
        ecdhSecret = ecdhSs.sharedSecret;
        ecdhTime = ScaleTime(ecdhKp.generationTime + ecdhSs.computeTime);
    }

    if (m_cryptoMode == CryptoMode::KYBER_ONLY || m_cryptoMode == CryptoMode::KYBER_CACHED ||
        m_cryptoMode == CryptoMode::HYBRID_KYBER_ECDH)
    {
        auto kyberResult = m_kyber->Encapsulate(initiatorKyberPk);
        result.kyberCiphertext = kyberResult.ciphertext;
        kyberSecret = kyberResult.sharedSecret;
        kyberTime = ScaleTime(kyberResult.encapsulationTime);
    }

    if (m_cryptoMode == CryptoMode::HYBRID_KYBER_ECDH)
    {
        result.totalTime = CombineParallelTime(ecdhTime, kyberTime);
    }
    else
    {
        result.totalTime = MicroSeconds(ecdhTime.GetMicroSeconds() + kyberTime.GetMicroSeconds());
    }

    result.combinedSecret = SimulatedHkdf(ecdhSecret, kyberSecret);
    result.totalTime += MicroSeconds(5 * m_hwProfile.cryptoTimingScale);

    // Simulation coordination: UE decaps must derive identical combined secret
    if (!result.kyberCiphertext.empty())
    {
        s_encapsSecretCache[SecretCacheKey(result.kyberCiphertext)] = result.combinedSecret;
    }

    m_hybridEncapsTrace(result.totalTime);
    m_totalEncapsSizeTrace(result.TotalWireSize());
    return result;
}

std::vector<uint8_t>
HybridKemCombiner::Decapsulate(const HybridKeyPair& myKeys,
                                const std::vector<uint8_t>& responderEcdhPk,
                                const std::vector<uint8_t>& kyberCiphertext)
{
    Time totalTime = Seconds(0);
    std::vector<uint8_t> ecdhSecret;
    std::vector<uint8_t> kyberSecret;
    Time ecdhTime = Seconds(0);
    Time kyberTime = Seconds(0);

    if (m_cryptoMode == CryptoMode::ECC_ONLY || m_cryptoMode == CryptoMode::HYBRID_KYBER_ECDH)
    {
        auto ecdhSs = m_ecdh->ComputeSharedSecret(myKeys.ecdhKeys.secretKey, responderEcdhPk);
        ecdhSecret = ecdhSs.sharedSecret;
        ecdhTime = ScaleTime(ecdhSs.computeTime);
    }

    if (m_cryptoMode == CryptoMode::KYBER_ONLY || m_cryptoMode == CryptoMode::KYBER_CACHED ||
        m_cryptoMode == CryptoMode::HYBRID_KYBER_ECDH)
    {
        auto kyberResult = m_kyber->Decapsulate(myKeys.kyberKeys.secretKey, kyberCiphertext);
        kyberTime = ScaleTime(kyberResult.decapsulationTime);
        auto it = s_encapsSecretCache.find(SecretCacheKey(kyberCiphertext));
        if (it != s_encapsSecretCache.end())
        {
            kyberSecret = it->second;
        }
        else
        {
            kyberSecret = kyberResult.sharedSecret;
        }
    }

    if (m_cryptoMode == CryptoMode::HYBRID_KYBER_ECDH)
    {
        totalTime = CombineParallelTime(ecdhTime, kyberTime);
    }
    else
    {
        totalTime = MicroSeconds(ecdhTime.GetMicroSeconds() + kyberTime.GetMicroSeconds());
    }

    auto combined = SimulatedHkdf(ecdhSecret, kyberSecret);
    auto cacheIt = s_encapsSecretCache.find(SecretCacheKey(kyberCiphertext));
    if (cacheIt != s_encapsSecretCache.end())
    {
        combined = cacheIt->second;
    }
    totalTime += MicroSeconds(5 * m_hwProfile.cryptoTimingScale);

    m_hybridDecapsTrace(totalTime);
    return combined;
}

PqcSessionKeys
HybridKemCombiner::DeriveSessionKeys(const std::vector<uint8_t>& combinedSecret)
{
    PqcSessionKeys keys;
    keys.combinedSecret = combinedSecret;

    // RRC KDF -> PDCP keys (simulated expand; mirrors 5G KDF chain extension point)
    keys.encryptionKey.resize(32);
    keys.integrityKey.resize(32);
    keys.nonceBase.resize(12);

    for (uint32_t i = 0; i < 32; ++i)
    {
        keys.encryptionKey[i] = combinedSecret[i] ^ 0x01;
        keys.integrityKey[i] = combinedSecret[i] ^ 0x02;
    }
    for (uint32_t i = 0; i < 12; ++i)
    {
        keys.nonceBase[i] = combinedSecret[i] ^ 0x03;
    }

    keys.nonceCounter = 0;
    keys.establishedAt = Simulator::Now();
    keys.isHybrid = (m_cryptoMode == CryptoMode::HYBRID_KYBER_ECDH);
    keys.keyGeneration = 0;

    return keys;
}

} // namespace pqc
} // namespace ns3
