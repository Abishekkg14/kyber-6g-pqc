/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

/**
 * \file drone-swarm-pqc-sim.cc
 * \brief Drone swarm PQC security evaluation (primary experiment driver).
 */

#include "ns3/applications-module.h"
#include "ns3/command-line.h"
#include "ns3/config.h"
#include "ns3/core-module.h"
#include "ns3/energy-module.h"
#include "ns3/gauss-markov-mobility-model.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/nr-module.h"
#include "ns3/pqc-drone-app.h"
#include "ns3/pqc-metrics-collector.h"
#include "ns3/pqc-scenario-helper.h"
#include "ns3/pqc-security-helper.h"
#include "ns3/pqc-session-keys.h"
#include "ns3/aes-gcm-cipher.h"
#include "ns3/queue-item.h"

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <map>
#include <string>

using namespace ns3;
using namespace ns3::pqc;

NS_LOG_COMPONENT_DEFINE("DroneSwarmPqcSim");

std::map<uint64_t, Time> g_enqueueTimes;
Ptr<PqcMetricsCollector> g_metrics;

void
EnqueueTrace(Ptr<const QueueItem> item)
{
    if (!item || !item->GetPacket())
    {
        return;
    }
    g_enqueueTimes[item->GetPacket()->GetUid()] = Simulator::Now();
}

void
DequeueTrace(Ptr<const QueueItem> item)
{
    if (!item || !item->GetPacket())
    {
        return;
    }
    auto it = g_enqueueTimes.find(item->GetPacket()->GetUid());
    if (it != g_enqueueTimes.end())
    {
        Time delay = Simulator::Now() - it->second;
        if (g_metrics)
        {
            g_metrics->RecordQueueingDelay(delay);
        }
        g_enqueueTimes.erase(it);
    }
}

static void
ApplyDroneSpeed(NodeContainer drones, double speed)
{
    for (uint32_t i = 0; i < drones.GetN(); ++i)
    {
        auto gm = drones.Get(i)->GetObject<GaussMarkovMobilityModel>();
        if (gm)
        {
            gm->SetAttribute("MeanVelocity",
                             StringValue("ns3::UniformRandomVariable[Min=0.0|Max=" +
                                         std::to_string(speed) + "]"));
        }
        auto cv = drones.Get(i)->GetObject<ConstantVelocityMobilityModel>();
        if (cv)
        {
            Vector vel = cv->GetVelocity();
            double mag = std::sqrt(vel.x * vel.x + vel.y * vel.y + vel.z * vel.z);
            if (mag > 0)
            {
                cv->SetVelocity(Vector(speed, 0, 0));
            }
        }
    }
}

static void
InstallDroneApplications(NodeContainer drones,
                         Ptr<PqcMetricsCollector> metrics,
                         Time simTime,
                         uint32_t packetSize,
                         uint32_t dataRateKbps)
{
    Ptr<Node> commander = drones.Get(0);
    Ptr<Ipv4> cmdrIpv4 = commander->GetObject<Ipv4>();
    if (!cmdrIpv4 || cmdrIpv4->GetNInterfaces() < 2)
    {
        return;
    }

    Ipv4Address cmdrAddr = cmdrIpv4->GetAddress(1, 0).GetLocal();
    uint16_t port = 9999;

    Ptr<AesGcmCipher> cmdrCipher = CreateObject<AesGcmCipher>();
    Ptr<PqcDroneApp> cmdrApp = CreateObject<PqcDroneApp>();
    cmdrApp->Setup(true, Ipv4Address::GetAny(), port, cmdrCipher, metrics);
    commander->AddApplication(cmdrApp);
    cmdrApp->SetStartTime(Seconds(0.5));
    cmdrApp->SetStopTime(simTime);

    PqcSessionKeys dummyKeys;
    dummyKeys.combinedSecret.resize(32, 0x42);
    dummyKeys.encryptionKey.resize(32, 0x42);
    dummyKeys.integrityKey.resize(32, 0x42);
    dummyKeys.nonceBase.resize(12, 0x00);
    Simulator::Schedule(Seconds(1.2), &AesGcmCipher::InstallKeys, cmdrCipher, dummyKeys);

    for (uint32_t i = 1; i < drones.GetN(); ++i)
    {
        Ptr<Node> drone = drones.Get(i);
        Ptr<AesGcmCipher> cipher = CreateObject<AesGcmCipher>();
        Ptr<PqcDroneApp> droneApp = CreateObject<PqcDroneApp>();
        double interval = (packetSize * 8.0) / (dataRateKbps * 1000.0);
        droneApp->SetAttribute("PacketSize", UintegerValue(packetSize));
        droneApp->SetAttribute("Interval", TimeValue(Seconds(interval)));
        droneApp->Setup(false, cmdrAddr, port, cipher, metrics);
        drone->AddApplication(droneApp);
        droneApp->SetStartTime(Seconds(1.0 + i * 0.05));
        droneApp->SetStopTime(simTime);
        Simulator::Schedule(Seconds(1.2 + i * 0.05), &AesGcmCipher::InstallKeys, cipher, dummyKeys);
    }
}

static void
InstallEnergyModel(NodeContainer drones, double batteryWh)
{
    BasicEnergySourceHelper basicSourceHelper;
    double energyJ = batteryWh * 3600.0 * 14.8; // MODELED: 14.8V nominal
    basicSourceHelper.Set("BasicEnergySourceInitialEnergyJ", DoubleValue(energyJ));
    basicSourceHelper.Install(drones);
}

static void
RevocationSignal(PqcSecurityHelper* pqcHelper, uint32_t droneId)
{
    pqcHelper->PurgeCache(droneId);
}

static CryptoMode
ResolveCryptoMode(const std::string& crypto, PqcScenarioId scenarioId)
{
    std::string lower = crypto;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower == "ecc" || lower == "baseline-ecc")
        return CryptoMode::ECC_ONLY;
    if (lower == "kyber" || lower == "kyber768" || lower == "kyber512" || lower == "kyber1024")
        return CryptoMode::KYBER_ONLY;
    if (lower == "kyber_cached" || lower == "kyber768-cached")
        return CryptoMode::KYBER_CACHED;
    if (lower == "hybrid" || lower == "hybrid-kyber768-x25519")
        return CryptoMode::HYBRID_KYBER_ECDH;

    switch (scenarioId)
    {
    case PqcScenarioId::BASELINE_ECC:
        return CryptoMode::ECC_ONLY;
    case PqcScenarioId::KYBER512:
    case PqcScenarioId::KYBER768:
    case PqcScenarioId::KYBER1024:
        return CryptoMode::KYBER_ONLY;
    case PqcScenarioId::KYBER768_CACHED:
        return CryptoMode::KYBER_CACHED;
    case PqcScenarioId::HYBRID_KYBER768_X25519_CACHED:
        return CryptoMode::HYBRID_KYBER_ECDH;
    default:
        return CryptoMode::HYBRID_KYBER_ECDH;
    }
}

static CrystalsKyberKem::SecurityLevel
ResolveKyberLevel(const std::string& crypto, uint32_t kyberLevelArg, PqcScenarioId scenarioId)
{
    if (kyberLevelArg == 512)
        return CrystalsKyberKem::KYBER_512;
    if (kyberLevelArg == 1024)
        return CrystalsKyberKem::KYBER_1024;
    std::string lower = crypto;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower.find("512") != std::string::npos)
        return CrystalsKyberKem::KYBER_512;
    if (lower.find("1024") != std::string::npos)
        return CrystalsKyberKem::KYBER_1024;
    if (scenarioId == PqcScenarioId::KYBER512)
        return CrystalsKyberKem::KYBER_512;
    if (scenarioId == PqcScenarioId::KYBER1024)
        return CrystalsKyberKem::KYBER_1024;
    return CrystalsKyberKem::KYBER_768;
}

static int
RunSingleSimulation(const std::string& cryptoModeStr,
                    uint32_t numDrones,
                    double speed,
                    uint32_t packetSize,
                    uint32_t dataRateKbps,
                    double simTime,
                    uint32_t kyberLevelArg,
                    bool parallelHandshake,
                    bool cacheEnabled,
                    double cacheTtlSec,
                    bool cacheRevocation,
                    double edgeBackhaulMs,
                    const std::string& scenarioStr,
                    bool nlosEnabled,
                    bool urbanCanyon,
                    const std::string& hardwareProfile,
                    double batteryWh,
                    uint32_t runIndex,
                    uint32_t seed)
{
    PqcScenarioId scenarioId = ParseScenarioId(scenarioStr);
    PqcScenarioConfig scfg;
    scfg.speed = speed;
    scfg.nlosEnabled = nlosEnabled;
    scfg.urbanCanyon = urbanCanyon;
    scfg.edgeBackhaulDelay = MilliSeconds(edgeBackhaulMs);
    scfg.enableHandover = (scenarioId == PqcScenarioId::HIGH_SPEED_HANDOVER);

    PqcScenarioHelper scenarioHelper;
    scenarioHelper.SetConfig(scfg);

    PqcScenarioHelper::ScenarioResult scenarioResult;
    if (!scenarioStr.empty() && scenarioStr != "auto")
    {
        scenarioResult = scenarioHelper.CreateFromScenarioId(scenarioId, numDrones);
    }
    else if (numDrones <= 20)
    {
        scenarioResult = scenarioHelper.CreateBaselineScenario(numDrones);
    }
    else
    {
        uint32_t uesPerGnb = (numDrones + 6) / 7;
        scenarioResult = scenarioHelper.CreateDenseUrbanScenario(uesPerGnb);
    }

    uint32_t actualDrones = scenarioResult.ueNodes.GetN();
    ApplyDroneSpeed(scenarioResult.ueNodes, speed);

    PqcSecurityHelper pqcHelper;
    g_metrics = pqcHelper.GetMetricsCollector();
    g_metrics->SetNodeCount(actualDrones);

    CryptoMode mode = ResolveCryptoMode(cryptoModeStr, scenarioId);
    if (scenarioId == PqcScenarioId::HYBRID_KYBER768_X25519_CACHED ||
        scenarioId == PqcScenarioId::KYBER768_CACHED)
    {
        mode = (scenarioId == PqcScenarioId::KYBER768_CACHED) ? CryptoMode::KYBER_CACHED
                                                              : CryptoMode::HYBRID_KYBER_ECDH;
        cacheEnabled = true;
    }

    auto kyberLevel = ResolveKyberLevel(cryptoModeStr, kyberLevelArg, scenarioId);
    pqcHelper.SetCryptoMode(mode);
    pqcHelper.SetKyberLevel(kyberLevel);
    pqcHelper.SetParallelHandshake(parallelHandshake);
    pqcHelper.SetHardwareProfile(hardwareProfile);
    pqcHelper.SetCacheEnabled(cacheEnabled);
    pqcHelper.SetCacheTtl(Seconds(cacheTtlSec));
    pqcHelper.SetCacheRevocationEnabled(cacheRevocation);
    pqcHelper.SetEdgeBackhaulDelay(MilliSeconds(edgeBackhaulMs));
    pqcHelper.SetBatteryWh(batteryWh);

    if (scenarioId == PqcScenarioId::QUANTUM_ATTACK)
    {
        pqcHelper.SetEnableQuantumAttacker(true);
    }

    pqcHelper.Install(scenarioResult.gnbDevices, scenarioResult.ueDevices);
    pqcHelper.ScheduleHandshakes(MilliSeconds(800));

    if (cacheEnabled)
    {
        pqcHelper.ScheduleHandshakes(Seconds(2.0));
    }

    // NR MAC queue traces vary by ns-3/NR version; queueing_delay_us also derived from RRC overhead model.

    InstallDroneApplications(scenarioResult.ueNodes,
                           pqcHelper.GetMetricsCollector(),
                           Seconds(simTime),
                           packetSize,
                           dataRateKbps);
    InstallEnergyModel(scenarioResult.ueNodes, batteryWh);

  double revTime = std::min(simTime * 0.5, 300.0);
    if (cacheRevocation)
    {
        Simulator::Schedule(Seconds(revTime), &RevocationSignal, &pqcHelper, 1u);
    }

    Simulator::Stop(Seconds(simTime + 1.0));
    Simulator::Run();

    if (scenarioId == PqcScenarioId::QUANTUM_ATTACK)
    {
        pqcHelper.RunQuantumAttack();
    }

    pqcHelper.GetMetricsCollector()->RecordCacheHitRate(pqcHelper.GetKeyCache()->GetHitRate());
    pqcHelper.GetMetricsCollector()->RecordStaleKeyEvent(pqcHelper.GetKeyCache()->GetStaleKeyEvents());
    pqcHelper.GetMetricsCollector()->RecordRevokedKeyReuseAttempt(
        pqcHelper.GetKeyCache()->GetRevokedReuseAttempts());

    pqcHelper.GetMetricsCollector()->ExportIntermediateLogs("results_data");

    if (system("mkdir -p results results/metadata")) {
    }

    std::string csvName = "results/" + cryptoModeStr + "_" + std::to_string(actualDrones) + "nodes";
    if (runIndex > 0)
    {
        csvName += "_run" + std::to_string(runIndex);
    }
    csvName += ".csv";

    pqcHelper.GetMetricsCollector()->ExportToCsv(csvName);

    std::string metaName = "results/metadata/" + cryptoModeStr + "_" +
                           std::to_string(actualDrones) + "nodes_run" + std::to_string(runIndex) +
                           ".meta";
    pqcHelper.ExportRunMetadata(metaName, seed, runIndex, scenarioStr);

    std::map<std::string, std::string> meta;
    meta["seed"] = std::to_string(seed);
    meta["run_index"] = std::to_string(runIndex);
    meta["scenario"] = scenarioStr;
    meta["crypto_mode"] = cryptoModeStr;
    meta["nodes"] = std::to_string(actualDrones);
    pqcHelper.GetMetricsCollector()->ExportMetadataJson(
        metaName + ".json",
        meta);

    pqcHelper.GetMetricsCollector()->PrintSummary();
    Simulator::Destroy();
    return 0;
}

int
main(int argc, char* argv[])
{
    std::string cryptoModeStr = "hybrid";
    std::string cryptoAlias;
    std::string scenarioStr = "auto";
    std::string hardwareProfile = "jetson-nano";
    uint32_t numDrones = 20;
    uint32_t numRuns = 1;
    uint32_t seed = 42;
    uint32_t kyberLevelArg = 768;
    std::string hybridModeStr = "kyber768-x25519";
    bool parallelHandshake = false;
    bool cacheEnabled = false;
    double cacheTtlSec = 300.0;
    bool cacheRevocation = false;
    double edgeBackhaulMs = 2.0;
    bool nlosEnabled = false;
    bool urbanCanyon = false;
    double speed = 25.0;
    double batteryWh = 74.0;
    uint32_t packetSize = 1024;
    uint32_t dataRateKbps = 200;
    double simTime = 10.0;

    CommandLine cmd;
    cmd.AddValue("cryptoMode", "Cryptography mode: ecc, kyber, kyber_cached, hybrid", cryptoModeStr);
    cmd.AddValue("crypto", "Alias for cryptoMode", cryptoAlias);
    cmd.AddValue("nodes", "Number of drone nodes", numDrones);
    cmd.AddValue("nDrones", "Alias for nodes", numDrones);
    cmd.AddValue("numRuns", "Monte Carlo run count (default 1, use >=30 for publication)", numRuns);
    cmd.AddValue("seed", "RNG seed base", seed);
    cmd.AddValue("RngRun", "Alias for seed offset (legacy ablation compat)", seed);
    cmd.AddValue("kyberLevel", "Kyber level: 512, 768, 1024", kyberLevelArg);
    cmd.AddValue("hybridMode", "Hybrid variant label", hybridModeStr);
    cmd.AddValue("parallelHandshake", "Run ECDH+Kyber in parallel when hardware allows", parallelHandshake);
    cmd.AddValue("cacheEnabled", "Enable mobility-aware PQC key cache", cacheEnabled);
    cmd.AddValue("cacheTtl", "Cache TTL in seconds", cacheTtlSec);
    cmd.AddValue("cacheRevocation", "Trigger cache revocation mid-simulation", cacheRevocation);
    cmd.AddValue("edgeBackhaulMs", "MEC edge backhaul latency (ms)", edgeBackhaulMs);
    cmd.AddValue("scenario", "Scenario name (see docs/simulation-methodology.md)", scenarioStr);
    cmd.AddValue("nlosEnabled", "Enable NLOS shadowing", nlosEnabled);
    cmd.AddValue("urbanCanyon", "Urban canyon propagation stress", urbanCanyon);
    cmd.AddValue("speed", "Drone mobility speed m/s", speed);
    cmd.AddValue("batteryWh", "Battery capacity in Wh (MODELED)", batteryWh);
    cmd.AddValue("hardwareProfile",
                 "Hardware profile: cortex-a55, jetson-nano, jetson-orin, pixhawk-class, edge-server",
                 hardwareProfile);
    cmd.AddValue("packetSize", "Telemetry payload bytes", packetSize);
    cmd.AddValue("rate", "Data rate kbps per drone", dataRateKbps);
    cmd.AddValue("simTime", "Simulation duration seconds", simTime);
    cmd.Parse(argc, argv);

    if (!cryptoAlias.empty())
    {
        cryptoModeStr = cryptoAlias;
    }

    if (cryptoModeStr == "kyber_cached" || cryptoModeStr == "kyber768-cached")
    {
        cacheEnabled = true;
    }

    for (uint32_t run = 0; run < numRuns; ++run)
    {
        RngSeedManager::SetSeed(seed + run);
        RngSeedManager::SetRun(run + 1);
        NS_LOG_UNCOND("Run " << (run + 1) << "/" << numRuns << " seed=" << (seed + run));
        RunSingleSimulation(cryptoModeStr,
                            numDrones,
                            speed,
                            packetSize,
                            dataRateKbps,
                            simTime,
                            kyberLevelArg,
                            parallelHandshake,
                            cacheEnabled,
                            cacheTtlSec,
                            cacheRevocation,
                            edgeBackhaulMs,
                            scenarioStr,
                            nlosEnabled,
                            urbanCanyon,
                            hardwareProfile,
                            batteryWh,
                            run,
                            seed + run);
    }

    return 0;
}
