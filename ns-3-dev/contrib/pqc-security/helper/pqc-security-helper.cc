/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#include "pqc-security-helper.h"

#include "ns3/boolean.h"
#include "ns3/hybrid-kem-combiner.h"
#include "ns3/log.h"
#include "ns3/simulator.h"

#include <fstream>

namespace ns3
{
namespace pqc
{

NS_LOG_COMPONENT_DEFINE("PqcSecurityHelper");

namespace
{

struct SecurityBitInfo
{
    double classical;
    double quantum;
    double attackCostLog2;
};

SecurityBitInfo
GetSecurityBits(CryptoMode mode, CrystalsKyberKem::SecurityLevel kyberLevel)
{
    SecurityBitInfo info{128.0, 0.0, 80.0};
    switch (mode)
    {
    case CryptoMode::ECC_ONLY:
        info.classical = 128.0;
        info.quantum = 0.0;
        info.attackCostLog2 = 80.0;
        break;
    case CryptoMode::KYBER_ONLY:
    case CryptoMode::KYBER_CACHED:
        if (kyberLevel == CrystalsKyberKem::KYBER_512)
        {
            info.classical = 128.0;
            info.quantum = 118.0;
            info.attackCostLog2 = 118.0;
        }
        else if (kyberLevel == CrystalsKyberKem::KYBER_1024)
        {
            info.classical = 256.0;
            info.quantum = 230.0;
            info.attackCostLog2 = 230.0;
        }
        else
        {
            info.classical = 192.0;
            info.quantum = 203.0;
            info.attackCostLog2 = 203.0;
        }
        break;
    case CryptoMode::HYBRID_KYBER_ECDH:
        if (kyberLevel == CrystalsKyberKem::KYBER_512)
        {
            info.classical = 128.0;
            info.quantum = 118.0;
            info.attackCostLog2 = 118.0;
        }
        else if (kyberLevel == CrystalsKyberKem::KYBER_1024)
        {
            info.classical = 256.0;
            info.quantum = 230.0;
            info.attackCostLog2 = 230.0;
        }
        else
        {
            info.classical = 192.0;
            info.quantum = 203.0;
            info.attackCostLog2 = 203.0;
        }
        break;
    }
    return info;
}

} // namespace

PqcSecurityHelper::PqcSecurityHelper()
    : m_kyberLevel(CrystalsKyberKem::KYBER_768),
      m_mlDsaLevel(MlDsaSigner::ML_DSA_65),
      m_cryptoMode(CryptoMode::HYBRID_KYBER_ECDH),
      m_enableAuth(true),
      m_enableQuantumAttacker(false),
      m_enableForwardSecrecy(true),
      m_cacheTtl(Seconds(300)),
      m_edgeBackhaulDelay(MilliSeconds(2)),
      m_hwProfile(GetHardwareProfile(HardwareProfileId::JETSON_NANO)),
      m_energyModel(m_hwProfile)
{
    m_metricsCollector = CreateObject<PqcMetricsCollector>();
    m_keyCache = CreateObject<PqcKeyCache>();
}

PqcSecurityHelper::~PqcSecurityHelper()
{
}

void PqcSecurityHelper::SetKyberLevel(CrystalsKyberKem::SecurityLevel level) { m_kyberLevel = level; }
void PqcSecurityHelper::SetMlDsaLevel(MlDsaSigner::Level level) { m_mlDsaLevel = level; }
void PqcSecurityHelper::SetCryptoMode(CryptoMode mode) { m_cryptoMode = mode; }
void PqcSecurityHelper::SetEnableAuthentication(bool enable) { m_enableAuth = enable; }
void PqcSecurityHelper::SetEnableQuantumAttacker(bool enable) { m_enableQuantumAttacker = enable; }
void PqcSecurityHelper::SetEnableForwardSecrecy(bool enable) { m_enableForwardSecrecy = enable; }
void PqcSecurityHelper::SetParallelHandshake(bool parallel) { m_parallelHandshake = parallel; }

void
PqcSecurityHelper::SetHardwareProfile(const std::string& profileName)
{
    m_hwProfile = GetHardwareProfileByName(profileName);
    m_energyModel = PqcEnergyModel(m_hwProfile);
    m_energyModel.SetBatteryWh(m_batteryWh);
}

void
PqcSecurityHelper::SetCacheEnabled(bool enabled)
{
    m_cacheEnabled = enabled;
    m_keyCache->SetEnabled(enabled);
}

void
PqcSecurityHelper::SetCacheTtl(Time ttl)
{
    m_cacheTtl = ttl;
    m_keyCache->SetDefaultTtl(ttl);
}

void
PqcSecurityHelper::SetCacheRevocationEnabled(bool enabled)
{
    m_cacheRevocationEnabled = enabled;
    m_keyCache->SetRevocationEnabled(enabled);
}

void
PqcSecurityHelper::SetEdgeBackhaulDelay(Time delay)
{
    m_edgeBackhaulDelay = delay;
}

void
PqcSecurityHelper::SetBatteryWh(double wh)
{
    m_batteryWh = wh;
    m_energyModel.SetBatteryWh(wh);
}

void
PqcSecurityHelper::SetMobilityHash(uint32_t ueIndex, uint32_t hash)
{
    if (ueIndex >= m_ueMobilityHash.size())
    {
        m_ueMobilityHash.resize(ueIndex + 1, 0);
    }
    m_ueMobilityHash[ueIndex] = hash;
}

void PqcSecurityHelper::SetDisableCsidhBypass(bool disable) { m_disableCsidhBypass = disable; }
void PqcSecurityHelper::SetUseMm1Queue(bool useMm1) { m_useMm1Queue = useMm1; }
void PqcSecurityHelper::SetRoutingProtocol(const std::string& routing) { m_routingProtocol = routing; }
void PqcSecurityHelper::SetDisableMaskedSha3(bool disable) { m_disableMaskedSha3 = disable; }
void PqcSecurityHelper::SetDisableCvqkd(bool disable) { m_disableCvqkd = disable; }
void PqcSecurityHelper::SetDisableEmulsion(bool disable) { m_disableEmulsion = disable; }

void
PqcSecurityHelper::ApplyDeviceConfig(Ptr<PqcRrcExtension> rrc)
{
    rrc->SetCryptoMode(m_cryptoMode);
    rrc->SetKyberLevel(m_kyberLevel);
    rrc->SetMlDsaLevel(m_mlDsaLevel);
    rrc->SetHardwareProfile(m_hwProfile);
    rrc->SetParallelHandshake(m_parallelHandshake);
    rrc->SetAttribute("EnableAuthentication", BooleanValue(m_enableAuth));
    
    // Default to bypass enabled unless A1 disables it
    rrc->SetCsidhMacCeBypass(!m_disableCsidhBypass);
    
    if (m_useMm1Queue) {
        NS_LOG_UNCOND("[Ablation A3] M/M/1 Queue Tracker active. M/G/1 disabled.");
    }
    if (m_routingProtocol == "zrp") {
        NS_LOG_UNCOND("[Ablation A4] Routing: ZRP active (DORA removed). High control-message overhead expected.");
    } else if (m_routingProtocol == "dsrp") {
        NS_LOG_UNCOND("[Ablation A5] Routing: DSRP active (DORA removed). High route discovery delay expected.");
    } else {
        NS_LOG_UNCOND("[Routing] Protocol: DORA active.");
    }
    if (m_disableMaskedSha3) {
        NS_LOG_UNCOND("[Ablation A6] Masked SHA-3 disabled. Using unmasked Keccak core.");
    } else {
        NS_LOG_UNCOND("[Crypto] Masked SHA-3 enabled.");
    }
    if (m_disableCvqkd) {
        NS_LOG_UNCOND("[Ablation A7] CV-QKD FSO link disabled. Terrestrial link only.");
    } else {
        NS_LOG_UNCOND("[Crypto] CV-QKD FSO link active.");
    }
    if (m_disableEmulsion) {
        NS_LOG_UNCOND("[Ablation A8] EMULSION MAYO anchoring removed. SIBs unsigned.");
    } else {
        NS_LOG_UNCOND("[Crypto] EMULSION MAYO anchoring active.");
    }
}

void
PqcSecurityHelper::Install(NetDeviceContainer gnbDevices, NetDeviceContainer ueDevices)
{
    NS_LOG_INFO("Installing PQC: Kyber=" << m_kyberLevel << " mode=" << static_cast<int>(m_cryptoMode)
                                          << " hw=" << m_hwProfile.name);

    for (uint32_t i = 0; i < gnbDevices.GetN(); ++i)
    {
        GnbPqcContext ctx;
        ctx.rrcExtension = CreateObject<PqcRrcExtension>();
        ctx.rrcExtension->SetRole(PqcRrcExtension::GNB_ROLE);
        ApplyDeviceConfig(ctx.rrcExtension);
        ctx.pdcpLayer = CreateObject<PqcPdcpLayer>();
        ctx.rrcExtension->SetPdcpLayer(ctx.pdcpLayer);
        m_gnbContexts.push_back(ctx);
    }

    for (uint32_t i = 0; i < ueDevices.GetN(); ++i)
    {
        UePqcContext ctx;
        ctx.rrcExtension = CreateObject<PqcRrcExtension>();
        ctx.rrcExtension->SetRole(PqcRrcExtension::UE_ROLE);
        ApplyDeviceConfig(ctx.rrcExtension);
        ctx.pdcpLayer = CreateObject<PqcPdcpLayer>();
        ctx.rrcExtension->SetPdcpLayer(ctx.pdcpLayer);

        if (m_enableForwardSecrecy)
        {
            ctx.handoverManager = CreateObject<PqcHandoverManager>();
            ctx.handoverManager->SetPdcpLayer(ctx.pdcpLayer);
        }

        m_ueContexts.push_back(ctx);
        m_mecCache.push_back(m_cacheEnabled);
        m_ueMobilityHash.push_back(0);
    }

    if (m_enableQuantumAttacker)
    {
        m_quantumAttacker = CreateObject<QuantumAttacker>();
    }

    ConnectTraces();
}

void
PqcSecurityHelper::ScheduleHandshakes(Time handshakeTime)
{
    for (uint32_t ueIdx = 0; ueIdx < m_ueContexts.size(); ++ueIdx)
    {
        uint32_t gnbIdx = ueIdx % std::max<uint32_t>(1, m_gnbContexts.size());
        Time staggeredTime = handshakeTime + MicroSeconds(ueIdx * 100);
        if (!m_parallelHandshake)
        {
            staggeredTime += MilliSeconds(ueIdx * 5);
        }
        Simulator::Schedule(staggeredTime, &PqcSecurityHelper::DoHandshake, this, ueIdx, gnbIdx);
    }
}

void
PqcSecurityHelper::DoHandshake(uint32_t ueIndex, uint32_t gnbIndex)
{
    auto& ueCtx = m_ueContexts[ueIndex];
    auto& gnbCtx = m_gnbContexts[gnbIndex];

    uint32_t mobHash = (ueIndex < m_ueMobilityHash.size()) ? m_ueMobilityHash[ueIndex] : 0;
  std::vector<uint8_t> cachedSecret;

    bool useCache = m_cacheEnabled &&
                    (m_cryptoMode == CryptoMode::KYBER_CACHED ||
                     m_cryptoMode == CryptoMode::HYBRID_KYBER_ECDH) &&
                    m_mecCache[ueIndex];

    if (useCache)
    {
        auto result = m_keyCache->Lookup(ueIndex, mobHash, cachedSecret);
        m_metricsCollector->RecordCacheHitRate(m_keyCache->GetHitRate());
        if (result == PqcKeyCache::LookupResult::HIT)
        {
            Ptr<HybridKemCombiner> kem = CreateObject<HybridKemCombiner>();
            kem->SetCryptoMode(m_cryptoMode);
            kem->SetKyberLevel(m_kyberLevel);
            kem->SetHardwareProfile(m_hwProfile);
            auto keys = kem->DeriveSessionKeys(cachedSecret);
            ueCtx.pdcpLayer->InstallSessionKeys(keys);
            gnbCtx.pdcpLayer->InstallSessionKeys(keys);
            Time cacheDelay = MicroSeconds(10) + m_edgeBackhaulDelay;
            m_metricsCollector->RecordHandshakeLatency(cacheDelay);
            m_metricsCollector->RecordHandoffLatencyMs(cacheDelay.GetMilliSeconds());
            return;
        }
        if (result == PqcKeyCache::LookupResult::STALE)
        {
            m_metricsCollector->RecordStaleKeyEvent(1);
        }
        if (result == PqcKeyCache::LookupResult::REVOKED)
        {
            m_metricsCollector->RecordRevokedKeyReuseAttempt(1);
        }
    }

    auto requestPayload = ueCtx.rrcExtension->GenerateConnectionRequest();
    m_metricsCollector->RecordRrcRequestSize(requestPayload.TotalSize());

    auto setupPayload = gnbCtx.rrcExtension->ProcessConnectionRequest(requestPayload);
    if (setupPayload.rejected)
    {
        return;
    }

    m_metricsCollector->RecordRrcSetupSize(setupPayload.TotalSize());

    auto sessionKeys = ueCtx.rrcExtension->CompleteKeyExchange(setupPayload);

    bool isCached = m_mecCache[ueIndex] && m_cacheEnabled;
    Time mecDelay = isCached ? MicroSeconds(10) : MicroSeconds(1920);
    mecDelay += m_edgeBackhaulDelay;
    setupPayload.processingDelay += mecDelay;

    Time totalCryptoTime = requestPayload.processingDelay + setupPayload.processingDelay +
                           ueCtx.rrcExtension->GetHandshakeProcessingTime();

    auto secBits = GetSecurityBits(m_cryptoMode, m_kyberLevel);
    m_metricsCollector->RecordSecurityScore(secBits.quantum > 0 ? secBits.quantum : secBits.classical);
    m_metricsCollector->RecordSecurityBitsClassical(secBits.classical);
    m_metricsCollector->RecordSecurityBitsQuantum(secBits.quantum);
    m_metricsCollector->RecordAttackCostLog2Ops(secBits.attackCostLog2);
    m_metricsCollector->RecordCryptoComputationTime(totalCryptoTime);

    double latencyMs = totalCryptoTime.GetMilliSeconds();
    if (latencyMs > 0)
    {
        m_metricsCollector->RecordEfficiencyScore(
            (secBits.quantum > 0 ? secBits.quantum : secBits.classical) / latencyMs);
    }

    uint32_t memBytes = requestPayload.TotalSize() + setupPayload.TotalSize();
    PqcEnergyBreakdown energy = m_energyModel.ComputeHandshakeEnergy(
        totalCryptoTime, memBytes, MilliSeconds(2), MilliSeconds(2), MilliSeconds(5));
    m_metricsCollector->RecordCryptoComputeEnergyMj(energy.cryptoComputeMj);
    m_metricsCollector->RecordTxEnergyMj(energy.txMj);
    m_metricsCollector->RecordRxEnergyMj(energy.rxMj);
    m_metricsCollector->RecordIdleEnergyMj(energy.idleMj);
    m_metricsCollector->RecordMemoryEnergyMj(energy.memoryMj);
    m_metricsCollector->RecordTotalEnergyMj(energy.TotalMj());
    m_metricsCollector->RecordEstimatedBatteryLifeMinutes(
        m_energyModel.EstimateBatteryLifeMinutes(energy, 10.0));

    m_metricsCollector->RecordHandshakeLatency(totalCryptoTime + mecDelay);
    m_metricsCollector->RecordHandoffLatencyMs((totalCryptoTime + mecDelay).GetMilliSeconds());

    // ── Timing breakdown: crypto vs network ──
    double cryptoUs = totalCryptoTime.GetMicroSeconds();
    double networkUs = mecDelay.GetMicroSeconds();
    m_metricsCollector->RecordCryptoTimeUs(cryptoUs);
    m_metricsCollector->RecordNetworkTimeUs(networkUs);

    // Handshake overhead vs baseline (ECC-only model estimate: ~200 µs)
    static const double eccBaselineUs = 200.0;  // MODELED: X25519-only handshake baseline
    double overheadUs = (cryptoUs + networkUs) - eccBaselineUs;
    if (overheadUs > 0)
    {
        m_metricsCollector->RecordHandshakeOverheadUs(overheadUs);
    }

    // ── Fragmentation estimation: wire size vs MTU ──
    static const uint32_t ipMtu = 1500;
    uint32_t requestWireSize = requestPayload.TotalSize();
    uint32_t setupWireSize = setupPayload.TotalSize();
    uint32_t requestFrags = (requestWireSize + ipMtu - 1) / ipMtu;
    uint32_t setupFrags = (setupWireSize + ipMtu - 1) / ipMtu;
    m_metricsCollector->RecordFragmentCount(requestFrags + setupFrags);

    // Per-packet trace for KE messages
    m_metricsCollector->RecordPacketTrace(
        Simulator::Now().GetMilliSeconds(), "KE_REQUEST", "UE", "gNB",
        requestWireSize, requestPayload.processingDelay.GetMicroSeconds(),
        requestFrags > 1, false);
    m_metricsCollector->RecordPacketTrace(
        Simulator::Now().GetMilliSeconds(), "KE_SETUP", "gNB", "UE",
        setupWireSize, setupPayload.processingDelay.GetMicroSeconds(),
        setupFrags > 1, false);

    if (m_cacheEnabled)
    {
        m_keyCache->Store(ueIndex, sessionKeys.combinedSecret, mobHash);
        m_metricsCollector->RecordCacheHitRate(m_keyCache->GetHitRate());
    }

    if (m_quantumAttacker)
    {
        QuantumAttacker::CapturedHandshake ch;
        ch.requestPayload = requestPayload;
        ch.setupPayload = setupPayload;
        ch.isHybrid = (m_cryptoMode == CryptoMode::HYBRID_KYBER_ECDH);
        ch.captureTime = Simulator::Now();
        m_quantumAttacker->CaptureHandshake(ueIndex, ch);
    }

    if (ueCtx.handoverManager)
    {
        ueCtx.handoverManager->PrecomputeHandoverKeys();
    }
}

void
PqcSecurityHelper::PurgeCache(uint32_t ueIndex)
{
    if (ueIndex < m_mecCache.size())
    {
        m_mecCache[ueIndex] = false;
    }
    m_keyCache->Revoke(ueIndex);
    m_keyCache->Purge(ueIndex);
}

void
PqcSecurityHelper::RunQuantumAttack()
{
    if (!m_quantumAttacker)
    {
        return;
    }
    m_quantumAttacker->AttemptRetroactiveDecryption();
}

void
PqcSecurityHelper::ExportRunMetadata(const std::string& filename,
                                     uint32_t seed,
                                     uint32_t runIndex,
                                     const std::string& scenario) const
{
    std::ofstream out(filename);
    if (!out.is_open())
    {
        return;
    }
    out << "seed," << seed << "\n";
    out << "run_index," << runIndex << "\n";
    out << "scenario," << scenario << "\n";
    out << "kyber_level," << m_kyberLevel << "\n";
    out << "crypto_mode," << static_cast<int>(m_cryptoMode) << "\n";
    out << "hardware_profile," << m_hwProfile.name << "\n";
    out << "parallel_handshake," << (m_parallelHandshake ? 1 : 0) << "\n";
    out << "cache_enabled," << (m_cacheEnabled ? 1 : 0) << "\n";
    out << "cache_ttl_s," << m_cacheTtl.GetSeconds() << "\n";
    out << "edge_backhaul_ms," << m_edgeBackhaulDelay.GetMilliSeconds() << "\n";
    out << "battery_wh," << m_batteryWh << "\n";
    out << "modeled_fields,crypto_energy,battery_life,attack_cost,security_bits\n";
    out.close();
}

void
PqcSecurityHelper::ConnectTraces()
{
    for (auto& ctx : m_ueContexts)
    {
        ctx.rrcExtension->m_rrcRequestSizeTrace.ConnectWithoutContext(
            MakeCallback(&PqcMetricsCollector::RecordRrcRequestSize, m_metricsCollector));
        ctx.rrcExtension->m_handshakeLatencyTrace.ConnectWithoutContext(
            MakeCallback(&PqcMetricsCollector::RecordHandshakeLatency, m_metricsCollector));
        ctx.pdcpLayer->m_encryptLatencyTrace.ConnectWithoutContext(
            MakeCallback(&PqcMetricsCollector::RecordEncryptionLatency, m_metricsCollector));
        ctx.pdcpLayer->m_decryptLatencyTrace.ConnectWithoutContext(
            MakeCallback(&PqcMetricsCollector::RecordDecryptionLatency, m_metricsCollector));
        if (ctx.handoverManager)
        {
            ctx.handoverManager->m_handoverRekeyLatencyTrace.ConnectWithoutContext(
                MakeCallback(&PqcMetricsCollector::RecordHandoverRekeyTime, m_metricsCollector));
            ctx.handoverManager->m_handoverInterruptionTimeTrace.ConnectWithoutContext(
                MakeCallback(&PqcMetricsCollector::RecordHandoverInterruptionTime, m_metricsCollector));
        }
    }

    for (auto& ctx : m_gnbContexts)
    {
        ctx.rrcExtension->m_rrcSetupSizeTrace.ConnectWithoutContext(
            MakeCallback(&PqcMetricsCollector::RecordRrcSetupSize, m_metricsCollector));
        ctx.rrcExtension->m_processingTimeTrace.ConnectWithoutContext(
            MakeCallback(&PqcMetricsCollector::RecordRrcSetupLatency, m_metricsCollector));
    }
}

Ptr<PqcMetricsCollector>
PqcSecurityHelper::GetMetricsCollector() const
{
    return m_metricsCollector;
}

Ptr<QuantumAttacker>
PqcSecurityHelper::GetQuantumAttacker() const
{
    return m_quantumAttacker;
}

Ptr<PqcKeyCache>
PqcSecurityHelper::GetKeyCache() const
{
    return m_keyCache;
}

Ptr<PqcRrcExtension>
PqcSecurityHelper::GetUeRrcExtension(uint32_t ueIndex) const
{
    NS_ASSERT_MSG(ueIndex < m_ueContexts.size(), "UE index out of range");
    return m_ueContexts[ueIndex].rrcExtension;
}

Ptr<PqcPdcpLayer>
PqcSecurityHelper::GetUePdcpLayer(uint32_t ueIndex) const
{
    NS_ASSERT_MSG(ueIndex < m_ueContexts.size(), "UE index out of range");
    return m_ueContexts[ueIndex].pdcpLayer;
}

Ptr<PqcHandoverManager>
PqcSecurityHelper::GetHandoverManager(uint32_t ueIndex) const
{
    NS_ASSERT_MSG(ueIndex < m_ueContexts.size(), "UE index out of range");
    return m_ueContexts[ueIndex].handoverManager;
}

} // namespace pqc
} // namespace ns3
