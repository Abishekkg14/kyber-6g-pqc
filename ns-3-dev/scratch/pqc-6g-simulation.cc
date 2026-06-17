/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

/**
 * \file pqc-6g-simulation.cc
 * \brief Publication-ready 6G PQC security framework simulation.
 *
 * This simulation evaluates the performance impact of post-quantum
 * cryptography on 5G NR control and data planes using the PQC
 * security framework built on top of the 5G-LENA NR module.
 *
 * Experiments:
 *   1. Baseline functional test (1 gNB, 2 UEs, no PQC)
 *   2. PQC overhead test (1 gNB, 2 UEs, hybrid Kyber-768 + ML-DSA-65)
 *   3. Dense urban scalability (7 gNBs, 105 UEs, PQC enabled)
 *   4. High-speed mobility (5 gNBs, 10 UEs at 120+ m/s)
 *   5. Quantum attacker validation (prove HNDL attack fails with PQC)
 *
 * Usage:
 *   ./ns3 run "pqc-6g-simulation --scenario=baseline"
 *   ./ns3 run "pqc-6g-simulation --scenario=dense-urban --numUes=15"
 *   ./ns3 run "pqc-6g-simulation --scenario=high-speed --speed=120"
 *   ./ns3 run "pqc-6g-simulation --scenario=quantum-attack"
 *
 * Output:
 *   - Console log with handshake details and PQC metrics summary
 *   - pqc-metrics.csv: Statistical summary of all metrics
 *   - pqc-metrics_timeseries.csv: Per-sample timestamped data
 */

#include "ns3/applications-module.h"
#include "ns3/command-line.h"
#include "ns3/config.h"
#include "ns3/core-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/nr-module.h"
#include "ns3/point-to-point-helper.h"

#include <iomanip>


#include "ns3/pqc-scenario-helper.h"
#include "ns3/pqc-security-helper.h"
#include "ns3/pqc-metrics-collector.h"
#include "ns3/quantum-attacker.h"

using namespace ns3;
using namespace ns3::pqc;

NS_LOG_COMPONENT_DEFINE("Pqc6gSimulation");

// ═══════════════════════════════════════════════════════════
// Utility: Install UDP traffic application
// ═══════════════════════════════════════════════════════════

static void
InstallUdpTraffic(NodeContainer ueNodes,
                  Ptr<NrPointToPointEpcHelper> epcHelper,
                  Ptr<NrHelper> nrHelper,
                  Time startTime,
                  Time stopTime,
                  uint16_t dlPort = 1234,
                  uint32_t packetSize = 500,
                  double dataRateKbps = 100.0)
{
    Ptr<Node> pgw = epcHelper->GetPgwNode();

    // Install internet stack on pgw
    NodeContainer remoteHostContainer;
    remoteHostContainer.Create(1);
    Ptr<Node> remoteHost = remoteHostContainer.Get(0);
    InternetStackHelper internet;
    internet.Install(remoteHostContainer);

    PointToPointHelper p2pHelper;
    p2pHelper.SetDeviceAttribute("DataRate", DataRateValue(DataRate("100Gb/s")));
    p2pHelper.SetDeviceAttribute("Mtu", UintegerValue(2500));
    p2pHelper.SetChannelAttribute("Delay", TimeValue(MilliSeconds(2)));
    NetDeviceContainer internetDevices = p2pHelper.Install(pgw, remoteHost);

    Ipv4AddressHelper ipv4h;
    ipv4h.SetBase("1.0.0.0", "255.0.0.0");
    Ipv4InterfaceContainer internetIfs = ipv4h.Assign(internetDevices);

    Ipv4StaticRoutingHelper routingHelper;
    auto remoteHostRouting = routingHelper.GetStaticRouting(remoteHost->GetObject<Ipv4>());
    remoteHostRouting->AddNetworkRouteTo(Ipv4Address("7.0.0.0"),
                                       Ipv4Mask("255.0.0.0"),
                                       1);

    // Install UDP server on each UE
    UdpServerHelper ulPacketSinkHelper(dlPort);
    ApplicationContainer serverApps;
    for (uint32_t i = 0; i < ueNodes.GetN(); ++i)
    {
        serverApps.Add(ulPacketSinkHelper.Install(ueNodes.Get(i)));
    }
    serverApps.Start(startTime);

    // Install UDP client on remote host for each UE
    for (uint32_t i = 0; i < ueNodes.GetN(); ++i)
    {
        auto ueIpv4 = ueNodes.Get(i)->GetObject<Ipv4>();
        Ipv4Address ueAddr = ueIpv4->GetAddress(1, 0).GetLocal();

        UdpClientHelper ulClient(ueAddr, dlPort);
        ulClient.SetAttribute("PacketSize", UintegerValue(packetSize));

        double interval = (packetSize * 8.0) / (dataRateKbps * 1000.0);
        ulClient.SetAttribute("Interval", TimeValue(Seconds(interval)));
        ulClient.SetAttribute("MaxPackets", UintegerValue(0xFFFFFFFF));

        ApplicationContainer clientApp = ulClient.Install(remoteHost);
        clientApp.Start(startTime + MilliSeconds(100)); // Small offset
        clientApp.Stop(stopTime);
    }
}

// ═══════════════════════════════════════════════════════════
// Utility: Print flow monitor stats
// ═══════════════════════════════════════════════════════════

static void
PrintFlowMonitorStats(Ptr<FlowMonitor> monitor, Ptr<Ipv4FlowClassifier> classifier)
{
    auto stats = monitor->GetFlowStats();

    NS_LOG_UNCOND("");
    NS_LOG_UNCOND("╔═══════════════════════════════════════════╗");
    NS_LOG_UNCOND("║       FLOW MONITOR STATISTICS             ║");
    NS_LOG_UNCOND("╚═══════════════════════════════════════════╝");

    double totalThroughput = 0;
    uint32_t totalLost = 0;
    uint32_t flows = 0;

    for (auto& [flowId, stat] : stats)
    {
        auto fiveTuple = classifier->FindFlow(flowId);
        double throughput =
            stat.rxBytes * 8.0 / (stat.timeLastRxPacket.GetSeconds() -
                                   stat.timeFirstTxPacket.GetSeconds()) / 1e6;

        totalThroughput += throughput;
        totalLost += stat.lostPackets;
        flows++;

        if (flows <= 5) // Print details for first 5 flows
        {
            NS_LOG_UNCOND("  Flow " << flowId << " ("
                          << fiveTuple.sourceAddress << " → " << fiveTuple.destinationAddress
                          << ")");
            NS_LOG_UNCOND("    TX: " << stat.txPackets << " pkts, RX: " << stat.rxPackets
                          << " pkts, Lost: " << stat.lostPackets);
            NS_LOG_UNCOND("    Throughput: " << std::fixed << std::setprecision(2)
                          << throughput << " Mbps");
            if (stat.rxPackets > 0)
            {
                NS_LOG_UNCOND("    Mean delay: "
                              << (stat.delaySum.GetMicroSeconds() / stat.rxPackets) << " µs");
            }
        }
    }

    NS_LOG_UNCOND("  ────────────────────────────────────");
    NS_LOG_UNCOND("  Total flows: " << flows);
    NS_LOG_UNCOND("  Total throughput: " << std::fixed << std::setprecision(2)
                  << totalThroughput << " Mbps");
    NS_LOG_UNCOND("  Total lost packets: " << totalLost);
    NS_LOG_UNCOND("");
}

// ═══════════════════════════════════════════════════════════
// Main simulation
// ═══════════════════════════════════════════════════════════

int
main(int argc, char* argv[])
{
    // Default parameters
    std::string scenario = "baseline";
    uint32_t numUesPerGnb = 15;
    double speed = 120.0;
    double simTime = 5.0;
    std::string kyberLevel = "768";
    std::string mlDsaLevel = "65";
    bool enablePqc = true;
    bool enableQuantumAttacker = false;
    bool outputCsv = true;
    std::string csvPrefix = "pqc-metrics";
    uint32_t seed = 42;
    uint32_t numRuns = 1;
    double edgeBackhaulMs = 2.0;
    bool nlosEnabled = false;
    std::string hardwareProfile = "jetson-nano";

    CommandLine cmd;
    cmd.AddValue("scenario", "Scenario: baseline, dense-urban, high-speed, quantum-attack, dense-urban-nlos", scenario);
    cmd.AddValue("numUesPerGnb", "UEs per gNB (dense urban)", numUesPerGnb);
    cmd.AddValue("speed", "UE speed in m/s (high-speed)", speed);
    cmd.AddValue("simTime", "Simulation time in seconds", simTime);
    cmd.AddValue("kyberLevel", "Kyber security level: 512, 768, 1024", kyberLevel);
    cmd.AddValue("mlDsaLevel", "ML-DSA level: 44, 65, 87", mlDsaLevel);
    cmd.AddValue("enablePqc", "Enable PQC framework", enablePqc);
    cmd.AddValue("enableQuantumAttacker", "Enable quantum attacker", enableQuantumAttacker);
    cmd.AddValue("outputCsv", "Export metrics to CSV", outputCsv);
    cmd.AddValue("csvPrefix", "CSV output file prefix", csvPrefix);
    cmd.AddValue("seed", "RNG seed", seed);
    cmd.AddValue("numRuns", "Monte Carlo runs", numRuns);
    cmd.AddValue("edgeBackhaulMs", "MEC backhaul latency ms", edgeBackhaulMs);
    cmd.AddValue("nlosEnabled", "Enable NLOS shadowing", nlosEnabled);
    cmd.AddValue("hardwareProfile", "Hardware profile name", hardwareProfile);
    cmd.Parse(argc, argv);

    // Quantum attack scenario forces PQC + attacker
    if (scenario == "quantum-attack")
    {
        enablePqc = true;
        enableQuantumAttacker = true;
    }

    // Enable logging
    LogComponentEnable("Pqc6gSimulation", LOG_LEVEL_INFO);
    if (enablePqc)
    {
        LogComponentEnable("PqcSecurityHelper", LOG_LEVEL_INFO);
        LogComponentEnable("PqcRrcExtension", LOG_LEVEL_INFO);
        LogComponentEnable("PqcPdcpLayer", LOG_LEVEL_INFO);
        LogComponentEnable("PqcHandoverManager", LOG_LEVEL_INFO);
        if (enableQuantumAttacker)
        {
            LogComponentEnable("QuantumAttacker", LOG_LEVEL_INFO);
        }
    }

    // ── Print simulation configuration ──
    NS_LOG_UNCOND("");
    NS_LOG_UNCOND("╔════════════════════════════════════════════════════════════╗");
    NS_LOG_UNCOND("║           6G PQC SECURITY FRAMEWORK SIMULATION            ║");
    NS_LOG_UNCOND("║                Kyber-6G Project (2026)                     ║");
    NS_LOG_UNCOND("╚════════════════════════════════════════════════════════════╝");
    NS_LOG_UNCOND("  Scenario:     " << scenario);
    NS_LOG_UNCOND("  PQC:          " << (enablePqc ? "ENABLED" : "DISABLED (baseline)"));
    if (enablePqc)
    {
        NS_LOG_UNCOND("  Kyber level:  " << kyberLevel);
        NS_LOG_UNCOND("  ML-DSA level: " << mlDsaLevel);
    }
    NS_LOG_UNCOND("  Sim time:     " << simTime << " s");
    NS_LOG_UNCOND("");

    // ── Create the scenario ──
    PqcScenarioHelper scenarioHelper;
    PqcScenarioConfig scfg;
    scfg.edgeBackhaulDelay = MilliSeconds(edgeBackhaulMs);
    scfg.nlosEnabled = nlosEnabled || (scenario == "dense-urban-nlos");
    scfg.urbanCanyon = (scenario == "dense-urban-nlos");
    scfg.speed = speed;
    scenarioHelper.SetConfig(scfg);

    PqcScenarioHelper::ScenarioResult scenarioResult;

    if (scenario == "baseline" || scenario == "quantum-attack")
    {
        scenarioResult = scenarioHelper.CreateBaselineScenario(2);
    }
    else if (scenario == "dense-urban" || scenario == "dense-urban-nlos")
    {
        scenarioResult = scenarioHelper.CreateDenseUrbanScenario(numUesPerGnb);
    }
    else if (scenario == "high-speed")
    {
        scenarioResult = scenarioHelper.CreateHighSpeedMobilityScenario(5, 10, speed);
    }
    else
    {
        NS_FATAL_ERROR("Unknown scenario: " << scenario);
    }

    NS_LOG_UNCOND("  Topology: " << scenarioResult.numGnbs << " gNBs, "
                                  << scenarioResult.numUes << " UEs");
    NS_LOG_UNCOND("");

    // ── Install PQC framework ──
    PqcSecurityHelper pqcHelper;

    if (enablePqc)
    {
        // Configure Kyber level
        if (kyberLevel == "512")
            pqcHelper.SetKyberLevel(CrystalsKyberKem::KYBER_512);
        else if (kyberLevel == "768")
            pqcHelper.SetKyberLevel(CrystalsKyberKem::KYBER_768);
        else if (kyberLevel == "1024")
            pqcHelper.SetKyberLevel(CrystalsKyberKem::KYBER_1024);

        // Configure ML-DSA level
        if (mlDsaLevel == "44")
            pqcHelper.SetMlDsaLevel(MlDsaSigner::ML_DSA_44);
        else if (mlDsaLevel == "65")
            pqcHelper.SetMlDsaLevel(MlDsaSigner::ML_DSA_65);
        else if (mlDsaLevel == "87")
            pqcHelper.SetMlDsaLevel(MlDsaSigner::ML_DSA_87);

        pqcHelper.SetCryptoMode(enablePqc ? CryptoMode::HYBRID_KYBER_ECDH : CryptoMode::ECC_ONLY);
        pqcHelper.SetHardwareProfile(hardwareProfile);
        pqcHelper.SetEdgeBackhaulDelay(MilliSeconds(edgeBackhaulMs));
        pqcHelper.SetEnableAuthentication(true);
        pqcHelper.SetEnableQuantumAttacker(enableQuantumAttacker);
        pqcHelper.SetEnableForwardSecrecy(true);

        // Install on all devices
        pqcHelper.Install(scenarioResult.gnbDevices, scenarioResult.ueDevices);

        // Schedule PQC handshakes at t=0.5s (after NR attachment)
        pqcHelper.ScheduleHandshakes(MilliSeconds(500));
    }

    // ── Install UDP traffic ──
    InstallUdpTraffic(scenarioResult.ueNodes,
                       scenarioResult.epcHelper,
                       scenarioResult.nrHelper,
                       Seconds(1.0),       // start after handshake
                       Seconds(simTime),
                       1234,               // port
                       500,                // packet size
                       100.0);             // 100 kbps per UE

    // ── Install Flow Monitor ──
    FlowMonitorHelper flowMonHelper;
    auto flowMonitor = flowMonHelper.InstallAll();
    auto classifier = DynamicCast<Ipv4FlowClassifier>(flowMonHelper.GetClassifier());

    // ── Run simulation ──
    NS_LOG_UNCOND("Starting simulation...");
    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    // ── Post-simulation analysis ──
    NS_LOG_UNCOND("");
    NS_LOG_UNCOND("Simulation complete. Collecting results...");

    // Print flow monitor stats
    PrintFlowMonitorStats(flowMonitor, classifier);

    // Print PQC metrics
    if (enablePqc)
    {
        pqcHelper.GetMetricsCollector()->PrintSummary();

        // Export CSV
        if (outputCsv)
        {
            pqcHelper.GetMetricsCollector()->ExportToCsv(csvPrefix + ".csv");
        }
    }

    // Run quantum attack analysis
    if (enableQuantumAttacker)
    {
        NS_LOG_UNCOND("");
        NS_LOG_UNCOND("Running quantum attack analysis...");
        pqcHelper.RunQuantumAttack();
    }

    Simulator::Destroy();

    NS_LOG_UNCOND("");
    NS_LOG_UNCOND("═══ SIMULATION FINISHED ═══");
    NS_LOG_UNCOND("");

    return 0;
}
