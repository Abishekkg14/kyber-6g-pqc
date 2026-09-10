/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#ifndef PQC_SECURITY_HELPER_H
#define PQC_SECURITY_HELPER_H

#include "ns3/net-device-container.h"
#include "ns3/node-container.h"
#include "ns3/object-factory.h"
#include "ns3/crystals-kyber-kem.h"
#include "ns3/hardware-profile.h"
#include "ns3/ml-dsa-signer.h"
#include "ns3/pqc-energy-model.h"
#include "ns3/pqc-handover-manager.h"
#include "ns3/pqc-key-cache.h"
#include "ns3/pqc-metrics-collector.h"
#include "ns3/pqc-pdcp-layer.h"
#include "ns3/pqc-rrc-extension.h"
#include "ns3/quantum-attacker.h"

#include <map>
#include <vector>

namespace ns3
{
namespace pqc
{

/**
 * \brief One-line API to install the PQC security framework on NR devices.
 *
 * Usage:
 * \code
 *   PqcSecurityHelper pqc;
 *   pqc.SetKyberLevel(CrystalsKyberKem::KYBER_768);
 *   pqc.SetMlDsaLevel(MlDsaSigner::ML_DSA_65);
 *   pqc.SetEnableHybridKem(true);
 *   pqc.SetEnableQuantumAttacker(true);
 *   pqc.Install(gnbNetDevices, ueNetDevices);
 *
 *   // After simulation:
 *   pqc.GetMetricsCollector()->ExportToCsv("results.csv");
 * \endcode
 */
class PqcSecurityHelper
{
  public:
    PqcSecurityHelper();
    ~PqcSecurityHelper();

    // ── Configuration ──

    void SetKyberLevel(CrystalsKyberKem::SecurityLevel level);
    void SetMlDsaLevel(MlDsaSigner::Level level);
    void SetCryptoMode(CryptoMode mode);
    void SetEnableAuthentication(bool enable);
    void SetEnableQuantumAttacker(bool enable);
    void SetEnableForwardSecrecy(bool enable);
    void SetParallelHandshake(bool parallel);
    void SetHardwareProfile(const std::string& profileName);
    void SetCacheEnabled(bool enabled);
    void SetCacheTtl(Time ttl);
    void SetCacheRevocationEnabled(bool enabled);
    void SetEdgeBackhaulDelay(Time delay);
    void SetBatteryWh(double wh);
    void SetMobilityHash(uint32_t ueIndex, uint32_t hash);

    // Ablation toggles
    void SetDisableCsidhBypass(bool disable);
    void SetUseMm1Queue(bool useMm1);
    void SetRoutingProtocol(const std::string& routing);
    void SetDisableMaskedSha3(bool disable);
    void SetDisableCvqkd(bool disable);
    void SetDisableEmulsion(bool disable);

    void ExportRunMetadata(const std::string& filename,
                           uint32_t seed,
                           uint32_t runIndex,
                           const std::string& scenario) const;

    // ── Installation ──

    /**
     * \brief Install PQC security on all gNB and UE devices.
     *
     * Creates PqcRrcExtension and PqcPdcpLayer for each device,
     * performs the hybrid PQC handshake, and installs session keys.
     *
     * \param gnbDevices Container of gNB net devices.
     * \param ueDevices Container of UE net devices.
     */
    void Install(NetDeviceContainer gnbDevices, NetDeviceContainer ueDevices);

    /**
     * \brief Execute all PQC handshakes at the specified time.
     *
     * Schedules the hybrid KEM handshake for each UE-gNB pair.
     * \param handshakeTime When to begin the handshakes.
     */
    void ScheduleHandshakes(Time handshakeTime);

    /**
     * \brief Run the quantum attacker analysis after simulation.
     */
    void RunQuantumAttack();

    /**
     * \brief Purge the MEC cache for a specific UE node.
     */
    void PurgeCache(uint32_t ueIndex);

    // ── Accessors ──

    Ptr<PqcMetricsCollector> GetMetricsCollector() const;
    Ptr<QuantumAttacker> GetQuantumAttacker() const;

    /**
     * \brief Get the PQC RRC extension for a specific UE (by index).
     */
    Ptr<PqcRrcExtension> GetUeRrcExtension(uint32_t ueIndex) const;

    /**
     * \brief Get the PQC PDCP layer for a specific UE (by index).
     */
    Ptr<PqcPdcpLayer> GetUePdcpLayer(uint32_t ueIndex) const;

    /**
     * \brief Get the handover manager for a specific UE (by index).
     */
    Ptr<PqcHandoverManager> GetHandoverManager(uint32_t ueIndex) const;

    Ptr<PqcKeyCache> GetKeyCache() const;

  private:
    void ApplyDeviceConfig(Ptr<PqcRrcExtension> rrc);
    // Configuration
    CrystalsKyberKem::SecurityLevel m_kyberLevel;
    MlDsaSigner::Level m_mlDsaLevel;
    CryptoMode m_cryptoMode;
    bool m_enableAuth;
    bool m_enableQuantumAttacker;
    bool m_enableForwardSecrecy;
    bool m_parallelHandshake{false};
    bool m_cacheEnabled{true};
    bool m_cacheRevocationEnabled{true};
    Time m_cacheTtl;
    Time m_edgeBackhaulDelay;
    double m_batteryWh{74.0};
    HardwareProfile m_hwProfile;
    PqcEnergyModel m_energyModel;

    // Ablation state
    bool m_disableCsidhBypass{false};
    bool m_useMm1Queue{false};
    std::string m_routingProtocol{"dora"};
    bool m_disableMaskedSha3{false};
    bool m_disableCvqkd{false};
    bool m_disableEmulsion{false};

    // Per-device PQC objects
    struct UePqcContext
    {
        Ptr<PqcRrcExtension> rrcExtension;
        Ptr<PqcPdcpLayer> pdcpLayer;
        Ptr<PqcHandoverManager> handoverManager;
    };

    struct GnbPqcContext
    {
        Ptr<PqcRrcExtension> rrcExtension;
        Ptr<PqcPdcpLayer> pdcpLayer;
    };

    std::vector<UePqcContext> m_ueContexts;
    std::vector<GnbPqcContext> m_gnbContexts;
    std::vector<bool> m_mecCache;
    std::vector<uint32_t> m_ueMobilityHash;

    Ptr<PqcMetricsCollector> m_metricsCollector;
    Ptr<PqcKeyCache> m_keyCache;
    Ptr<QuantumAttacker> m_quantumAttacker;

    // Internal methods
    void DoHandshake(uint32_t ueIndex, uint32_t gnbIndex);
    void ConnectTraces();
};

} // namespace pqc
} // namespace ns3

#endif // PQC_SECURITY_HELPER_H
