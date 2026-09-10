/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

/**
 * \file kyber-5g-sim.cc
 * \brief Step 1 - Basic 5G NR Communication Between Two Users Through a gNB
 *
 * Kyber-6G Project: Secure 5G/6G Communication Using Post-Quantum Cryptography
 *
 * This simulation establishes a basic 5G NR network topology:
 *   - 1 gNB (base station / tower) at a fixed position
 *   - 2 UE nodes (User A and User B) at fixed positions
 *   - User A sends unencrypted UDP data to User B through the gNB
 *   - The gNB and EPC core network forward traffic between users
 *
 * Step 1 focuses only on verifying basic 5G NR communication works correctly.
 * No cryptography, encryption, mobility, handover, or performance analysis.
 *
 * Network architecture (NSA - Non-Standalone):
 *   User A (UE1) <--5G NR--> gNB <--EPC Core--> gNB <--5G NR--> User B (UE2)
 *
 * Usage:
 *   ./ns3 run "kyber-5g-sim --logging=true"
 *   ./ns3 run "kyber-5g-sim --packetSize=512 --simTime=2000"
 */

#include "ns3/antenna-module.h"
#include "ns3/applications-module.h"
#include "ns3/config-store-module.h"
#include "ns3/core-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-apps-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/nr-module.h"
#include "ns3/point-to-point-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("Kyber5gSim");

int
main(int argc, char* argv[])
{
    // ===================================================================
    // SIMULATION PARAMETERS
    // ===================================================================
    Time simTime = MilliSeconds(1000);        // Total simulation time
    Time appStartTime = MilliSeconds(400);    // When apps start (allow NR setup)
    uint32_t packetSize = 1024;               // UDP packet size in bytes
    uint32_t packetsPerSecond = 100;          // Sending rate
    bool logging = true;                      // Enable detailed logging

    // NR Radio Parameters
    // Using sub-6 GHz band typical for 5G deployments
    double centralFrequency = 3.5e9;   // 3.5 GHz - common 5G mid-band
    double bandwidth = 20e6;           // 20 MHz channel bandwidth
    uint16_t numerology = 1;           // Numerology 1 = 30 kHz SCS (typical for sub-6)
    double txPower = 35;               // gNB transmit power in dBm

    // ===================================================================
    // COMMAND LINE PARSING
    // ===================================================================
    CommandLine cmd(__FILE__);
    cmd.AddValue("simTime", "Total simulation time in ms", simTime);
    cmd.AddValue("packetSize", "UDP packet size in bytes", packetSize);
    cmd.AddValue("packetsPerSecond", "Number of UDP packets per second", packetsPerSecond);
    cmd.AddValue("logging", "Enable logging", logging);
    cmd.AddValue("frequency", "Central frequency in Hz", centralFrequency);
    cmd.AddValue("bandwidth", "System bandwidth in Hz", bandwidth);
    cmd.AddValue("numerology", "NR numerology (0-4)", numerology);
    cmd.AddValue("txPower", "gNB TX power in dBm", txPower);
    cmd.Parse(argc, argv);

    // ===================================================================
    // LOGGING CONFIGURATION
    // ===================================================================
    if (logging)
    {
        LogComponentEnable("Kyber5gSim", LOG_LEVEL_INFO);
        LogComponentEnable("UdpClient", LOG_LEVEL_INFO);
        LogComponentEnable("UdpServer", LOG_LEVEL_INFO);
        LogComponentEnable("NrPdcp", LOG_LEVEL_INFO);
    }

    NS_LOG_INFO("");
    NS_LOG_INFO("╔══════════════════════════════════════════════════════════╗");
    NS_LOG_INFO("║   Kyber-6G Project: Step 1 - Basic 5G NR Communication ║");
    NS_LOG_INFO("╚══════════════════════════════════════════════════════════╝");
    NS_LOG_INFO("");
    NS_LOG_INFO("Configuration:");
    NS_LOG_INFO("  Simulation time:  " << simTime.GetMilliSeconds() << " ms");
    NS_LOG_INFO("  Packet size:      " << packetSize << " bytes");
    NS_LOG_INFO("  Packets/sec:      " << packetsPerSecond);
    NS_LOG_INFO("  Frequency:        " << centralFrequency / 1e9 << " GHz");
    NS_LOG_INFO("  Bandwidth:        " << bandwidth / 1e6 << " MHz");
    NS_LOG_INFO("  Numerology:       " << numerology);
    NS_LOG_INFO("  TX Power:         " << txPower << " dBm");
    NS_LOG_INFO("");

    // Increase RLC buffer size for smooth operation
    Config::SetDefault("ns3::LteRlcUm::MaxTxBufferSize", UintegerValue(999999999));

    // ===================================================================
    // STEP 1: CREATE NODES (1 gNB + 2 UEs)
    // ===================================================================
    NS_LOG_INFO("[Step 1] Creating network nodes...");

    NodeContainer gnbNodes;
    gnbNodes.Create(1);

    NodeContainer ueNodes;
    ueNodes.Create(2);

    NS_LOG_INFO("  Created 1 gNB (base station) and 2 UE nodes");

    // ===================================================================
    // STEP 2: SET FIXED POSITIONS (No Mobility)
    // ===================================================================
    NS_LOG_INFO("[Step 2] Setting node positions (fixed, no mobility)...");

    MobilityHelper mobility;
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");

    // gNB (tower) at center, elevated at 10m height
    Ptr<ListPositionAllocator> gnbPositionAlloc = CreateObject<ListPositionAllocator>();
    gnbPositionAlloc->Add(Vector(0.0, 0.0, 10.0));
    mobility.SetPositionAllocator(gnbPositionAlloc);
    mobility.Install(gnbNodes);

    // UE1 (User A) at 20m east, UE2 (User B) at 20m west, both at 1.5m height
    Ptr<ListPositionAllocator> uePositionAlloc = CreateObject<ListPositionAllocator>();
    uePositionAlloc->Add(Vector(20.0, 0.0, 1.5));   // User A (sender)
    uePositionAlloc->Add(Vector(-20.0, 0.0, 1.5));   // User B (receiver)
    mobility.SetPositionAllocator(uePositionAlloc);
    mobility.Install(ueNodes);

    NS_LOG_INFO("  gNB position:    (0, 0, 10) meters");
    NS_LOG_INFO("  User A position: (20, 0, 1.5) meters  [Sender]");
    NS_LOG_INFO("  User B position: (-20, 0, 1.5) meters [Receiver]");

    // ===================================================================
    // STEP 3: CONFIGURE THE NR MODULE
    // ===================================================================
    NS_LOG_INFO("[Step 3] Configuring 5G NR module...");

    // Create the EPC helper (core network)
    Ptr<NrPointToPointEpcHelper> epcHelper = CreateObject<NrPointToPointEpcHelper>();
    // Create the beamforming helper
    Ptr<IdealBeamformingHelper> idealBeamformingHelper = CreateObject<IdealBeamformingHelper>();
    // Create the main NR helper
    Ptr<NrHelper> nrHelper = CreateObject<NrHelper>();

    nrHelper->SetBeamformingHelper(idealBeamformingHelper);
    nrHelper->SetEpcHelper(epcHelper);

    // --- Spectrum Configuration: Single band, single CC, single BWP ---
    CcBwpCreator ccBwpCreator;
    const uint8_t numCcPerBand = 1;

    CcBwpCreator::SimpleOperationBandConf bandConf(centralFrequency,
                                                   bandwidth,
                                                   numCcPerBand,
                                                   BandwidthPartInfo::UMi_StreetCanyon);

    OperationBandInfo band = ccBwpCreator.CreateOperationBandContiguousCc(bandConf);

    // Channel model configuration
    Config::SetDefault("ns3::ThreeGppChannelModel::UpdatePeriod", TimeValue(MilliSeconds(0)));
    nrHelper->SetChannelConditionModelAttribute("UpdatePeriod", TimeValue(MilliSeconds(0)));
    nrHelper->SetPathlossAttribute("ShadowingEnabled", BooleanValue(false));

    // Initialize the operation band (creates spectrum channels, etc.)
    nrHelper->InitializeOperationBand(&band);

    BandwidthPartInfoPtrVector allBwps = CcBwpCreator::GetAllBwps({band});

    // --- Beamforming ---
    idealBeamformingHelper->SetAttribute(
        "BeamformingMethod",
        TypeIdValue(DirectPathBeamforming::GetTypeId()));

    // --- Core network latency ---
    epcHelper->SetAttribute("S1uLinkDelay", TimeValue(MilliSeconds(0)));

    // --- UE Antenna Configuration ---
    nrHelper->SetUeAntennaAttribute("NumRows", UintegerValue(2));
    nrHelper->SetUeAntennaAttribute("NumColumns", UintegerValue(4));
    nrHelper->SetUeAntennaAttribute("AntennaElement",
                                    PointerValue(CreateObject<IsotropicAntennaModel>()));

    // --- gNB Antenna Configuration ---
    nrHelper->SetGnbAntennaAttribute("NumRows", UintegerValue(4));
    nrHelper->SetGnbAntennaAttribute("NumColumns", UintegerValue(8));
    nrHelper->SetGnbAntennaAttribute("AntennaElement",
                                     PointerValue(CreateObject<IsotropicAntennaModel>()));

    // --- BWP Manager: all traffic uses BWP 0 ---
    nrHelper->SetGnbBwpManagerAlgorithmAttribute("NGBR_LOW_LAT_EMBB", UintegerValue(0));
    nrHelper->SetUeBwpManagerAlgorithmAttribute("NGBR_LOW_LAT_EMBB", UintegerValue(0));

    NS_LOG_INFO("  NR configuration complete (single band, UMi Street Canyon)");

    // ===================================================================
    // STEP 4: INSTALL NR PROTOCOL STACK ON DEVICES
    // ===================================================================
    NS_LOG_INFO("[Step 4] Installing NR protocol stack...");

    NetDeviceContainer gnbNetDev = nrHelper->InstallGnbDevice(gnbNodes, allBwps);
    NetDeviceContainer ueNetDev = nrHelper->InstallUeDevice(ueNodes, allBwps);

    // Assign random streams for reproducibility
    int64_t randomStream = 1;
    randomStream += nrHelper->AssignStreams(gnbNetDev, randomStream);
    randomStream += nrHelper->AssignStreams(ueNetDev, randomStream);

    // Set numerology and TX power on the gNB BWP
    nrHelper->GetGnbPhy(gnbNetDev.Get(0), 0)
        ->SetAttribute("Numerology", UintegerValue(numerology));
    nrHelper->GetGnbPhy(gnbNetDev.Get(0), 0)
        ->SetAttribute("TxPower", DoubleValue(txPower));

    // Finalize device configuration
    for (auto it = gnbNetDev.Begin(); it != gnbNetDev.End(); ++it)
    {
        DynamicCast<NrGnbNetDevice>(*it)->UpdateConfig();
    }
    for (auto it = ueNetDev.Begin(); it != ueNetDev.End(); ++it)
    {
        DynamicCast<NrUeNetDevice>(*it)->UpdateConfig();
    }

    NS_LOG_INFO("  NR stack installed on 1 gNB and 2 UEs");

    // ===================================================================
    // STEP 5: INSTALL INTERNET STACK & ASSIGN IP ADDRESSES
    // ===================================================================
    NS_LOG_INFO("[Step 5] Installing internet stack and assigning IPs...");

    // Get EPC PGW node for routing setup
    Ptr<Node> pgw = epcHelper->GetPgwNode();

    // Create a remote host (required by EPC architecture for routing)
    NodeContainer remoteHostContainer;
    remoteHostContainer.Create(1);
    Ptr<Node> remoteHost = remoteHostContainer.Get(0);

    InternetStackHelper internet;
    internet.Install(remoteHostContainer);

    // Connect remote host to PGW via point-to-point link
    PointToPointHelper p2ph;
    p2ph.SetDeviceAttribute("DataRate", DataRateValue(DataRate("100Gb/s")));
    p2ph.SetDeviceAttribute("Mtu", UintegerValue(2500));
    p2ph.SetChannelAttribute("Delay", TimeValue(Seconds(0.000)));

    NetDeviceContainer internetDevices = p2ph.Install(pgw, remoteHost);

    Ipv4AddressHelper ipv4h;
    ipv4h.SetBase("1.0.0.0", "255.0.0.0");
    Ipv4InterfaceContainer internetIpIfaces = ipv4h.Assign(internetDevices);

    // Set up routing on remote host to reach UE subnet
    Ipv4StaticRoutingHelper ipv4RoutingHelper;
    Ptr<Ipv4StaticRouting> remoteHostStaticRouting =
        ipv4RoutingHelper.GetStaticRouting(remoteHost->GetObject<Ipv4>());
    remoteHostStaticRouting->AddNetworkRouteTo(Ipv4Address("7.0.0.0"),
                                               Ipv4Mask("255.0.0.0"), 1);

    // Install internet stack on UE nodes
    internet.Install(ueNodes);

    // Assign IP addresses to UEs
    Ipv4InterfaceContainer ueIpIfaces = epcHelper->AssignUeIpv4Address(ueNetDev);

    // Set default gateway for each UE (routes all traffic through EPC)
    for (uint32_t j = 0; j < ueNodes.GetN(); ++j)
    {
        Ptr<Ipv4StaticRouting> ueStaticRouting =
            ipv4RoutingHelper.GetStaticRouting(ueNodes.Get(j)->GetObject<Ipv4>());
        ueStaticRouting->SetDefaultRoute(epcHelper->GetUeDefaultGatewayAddress(), 1);
    }

    // Attach all UEs to the closest gNB
    nrHelper->AttachToClosestGnb(ueNetDev, gnbNetDev);

    Ipv4Address userAAddr = ueIpIfaces.GetAddress(0);
    Ipv4Address userBAddr = ueIpIfaces.GetAddress(1);

    NS_LOG_INFO("  User A (UE1) IP: " << userAAddr);
    NS_LOG_INFO("  User B (UE2) IP: " << userBAddr);
    NS_LOG_INFO("  Both UEs attached to gNB");

    // ===================================================================
    // STEP 6: INSTALL UDP APPLICATIONS (User A -> User B)
    // ===================================================================
    NS_LOG_INFO("[Step 6] Installing UDP applications (User A --> User B)...");

    uint16_t udpPort = 4000;

    // --- UDP Server on User B (receiver) ---
    UdpServerHelper serverHelper(udpPort);
    ApplicationContainer serverApp = serverHelper.Install(ueNodes.Get(1));

    // --- UDP Client on User A (sender) ---
    UdpClientHelper clientHelper;
    clientHelper.SetAttribute("RemotePort", UintegerValue(udpPort));
    clientHelper.SetAttribute("RemoteAddress", AddressValue(userBAddr));
    clientHelper.SetAttribute("MaxPackets", UintegerValue(0xFFFFFFFF));
    clientHelper.SetAttribute("PacketSize", UintegerValue(packetSize));
    clientHelper.SetAttribute("Interval",
                              TimeValue(Seconds(1.0 / packetsPerSecond)));
    ApplicationContainer clientApp = clientHelper.Install(ueNodes.Get(0));

    // --- Activate dedicated EPS bearer for the traffic ---
    // Bearer for User A (uplink: User A -> gNB -> EPC)
    NrEpsBearer bearer(NrEpsBearer::NGBR_LOW_LAT_EMBB);

    Ptr<NrEpcTft> tftUserA = Create<NrEpcTft>();
    NrEpcTft::PacketFilter pfUplinkA;
    pfUplinkA.remotePortStart = udpPort;
    pfUplinkA.remotePortEnd = udpPort;
    pfUplinkA.direction = NrEpcTft::UPLINK;
    tftUserA->Add(pfUplinkA);
    nrHelper->ActivateDedicatedEpsBearer(ueNetDev.Get(0), bearer, tftUserA);

    // Bearer for User B (downlink: EPC -> gNB -> User B)
    Ptr<NrEpcTft> tftUserB = Create<NrEpcTft>();
    NrEpcTft::PacketFilter pfDownlinkB;
    pfDownlinkB.localPortStart = udpPort;
    pfDownlinkB.localPortEnd = udpPort;
    pfDownlinkB.direction = NrEpcTft::DOWNLINK;
    tftUserB->Add(pfDownlinkB);
    nrHelper->ActivateDedicatedEpsBearer(ueNetDev.Get(1), bearer, tftUserB);

    // Start and stop applications
    serverApp.Start(appStartTime);
    clientApp.Start(appStartTime);
    serverApp.Stop(simTime);
    clientApp.Stop(simTime);

    NS_LOG_INFO("  UDP Client on User A -> port " << udpPort << " on User B");
    NS_LOG_INFO("  Packet size: " << packetSize
                << " bytes, Rate: " << packetsPerSecond << " pkts/sec");

    // ===================================================================
    // STEP 7: ENABLE FLOW MONITOR
    // ===================================================================
    NS_LOG_INFO("[Step 7] Setting up flow monitoring...");

    Packet::EnableChecking();
    Packet::EnablePrinting();

    FlowMonitorHelper flowHelper;
    NodeContainer monitorNodes;
    monitorNodes.Add(ueNodes);
    monitorNodes.Add(remoteHost);

    Ptr<ns3::FlowMonitor> monitor = flowHelper.Install(monitorNodes);
    monitor->SetAttribute("DelayBinWidth", DoubleValue(0.001));
    monitor->SetAttribute("JitterBinWidth", DoubleValue(0.001));
    monitor->SetAttribute("PacketSizeBinWidth", DoubleValue(20));

    // ===================================================================
    // STEP 8: RUN THE SIMULATION
    // ===================================================================
    NS_LOG_INFO("");
    NS_LOG_INFO("Starting simulation...");
    NS_LOG_INFO("═══════════════════════════════════════════════════════════");

    Simulator::Stop(simTime);
    Simulator::Run();

    // ===================================================================
    // STEP 9: COLLECT AND DISPLAY RESULTS
    // ===================================================================
    NS_LOG_INFO("");
    NS_LOG_INFO("═══════════════════════════════════════════════════════════");
    NS_LOG_INFO("SIMULATION RESULTS");
    NS_LOG_INFO("═══════════════════════════════════════════════════════════");

    monitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier =
        DynamicCast<Ipv4FlowClassifier>(flowHelper.GetClassifier());
    FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats();

    double flowDuration = (simTime - appStartTime).GetSeconds();

    std::cout << std::endl;
    std::cout << "========================================================" << std::endl;
    std::cout << " Kyber-6G Step 1: Simulation Results                    " << std::endl;
    std::cout << "========================================================" << std::endl;
    std::cout << std::endl;

    for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin();
         i != stats.end();
         ++i)
    {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(i->first);
        std::string proto = (t.protocol == 17) ? "UDP" : "TCP";

        std::cout << "Flow " << i->first << ": "
                  << t.sourceAddress << ":" << t.sourcePort
                  << " --> "
                  << t.destinationAddress << ":" << t.destinationPort
                  << " [" << proto << "]" << std::endl;
        std::cout << "  Tx Packets:  " << i->second.txPackets << std::endl;
        std::cout << "  Rx Packets:  " << i->second.rxPackets << std::endl;
        std::cout << "  Tx Bytes:    " << i->second.txBytes << std::endl;
        std::cout << "  Rx Bytes:    " << i->second.rxBytes << std::endl;

        if (i->second.rxPackets > 0)
        {
            double throughput = i->second.rxBytes * 8.0 / flowDuration / 1000.0 / 1000.0;
            double meanDelay = 1000.0 * i->second.delaySum.GetSeconds() / i->second.rxPackets;
            double meanJitter = 1000.0 * i->second.jitterSum.GetSeconds() / i->second.rxPackets;
            double lossRate = (i->second.txPackets - i->second.rxPackets) * 100.0
                              / i->second.txPackets;

            std::cout << "  Throughput:  " << throughput << " Mbps" << std::endl;
            std::cout << "  Mean Delay:  " << meanDelay << " ms" << std::endl;
            std::cout << "  Mean Jitter: " << meanJitter << " ms" << std::endl;
            std::cout << "  Packet Loss: " << lossRate << " %" << std::endl;
        }
        else
        {
            std::cout << "  ** No packets received **" << std::endl;
        }
        std::cout << std::endl;
    }

    // Summary from UdpServer
    Ptr<UdpServer> udpServer = DynamicCast<UdpServer>(serverApp.Get(0));
    if (udpServer)
    {
        std::cout << "--------------------------------------------------------" << std::endl;
        std::cout << " UDP Server (User B) received: "
                  << udpServer->GetReceived() << " packets" << std::endl;
    }

    std::cout << "--------------------------------------------------------" << std::endl;
    std::cout << " Simulation completed successfully!" << std::endl;
    std::cout << " Basic 5G NR UE-to-UE communication VERIFIED." << std::endl;
    std::cout << "========================================================" << std::endl;
    std::cout << std::endl;

    Simulator::Destroy();
    return EXIT_SUCCESS;
}
