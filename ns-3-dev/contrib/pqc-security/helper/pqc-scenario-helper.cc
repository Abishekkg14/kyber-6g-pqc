/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#include "pqc-scenario-helper.h"

#include "ns3/antenna-module.h"
#include "ns3/boolean.h"
#include "ns3/config.h"
#include "ns3/constant-velocity-mobility-model.h"
#include "ns3/double.h"
#include "ns3/ideal-beamforming-helper.h"
#include "ns3/internet-module.h"
#include "ns3/log.h"
#include "ns3/nr-module.h"
#include "ns3/point-to-point-helper.h"
#include "ns3/box.h"
#include "ns3/gauss-markov-mobility-model.h"
#include "ns3/pointer.h"
#include "ns3/uinteger.h"

#include <cmath>
#include <algorithm>
#include <cctype>

namespace ns3
{
namespace pqc
{

NS_LOG_COMPONENT_DEFINE("PqcScenarioHelper");

PqcScenarioId
ParseScenarioId(const std::string& name)
{
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower == "baseline-ecc" || lower == "baseline")
        return PqcScenarioId::BASELINE_ECC;
    if (lower == "kyber512")
        return PqcScenarioId::KYBER512;
    if (lower == "kyber768" || lower == "kyber")
        return PqcScenarioId::KYBER768;
    if (lower == "kyber1024")
        return PqcScenarioId::KYBER1024;
    if (lower == "kyber768-cached" || lower == "kyber_cached")
        return PqcScenarioId::KYBER768_CACHED;
    if (lower == "hybrid-kyber768-x25519" || lower == "hybrid")
        return PqcScenarioId::HYBRID_KYBER768_X25519;
    if (lower == "hybrid-kyber768-x25519-cached")
        return PqcScenarioId::HYBRID_KYBER768_X25519_CACHED;
    if (lower == "quantum-attack")
        return PqcScenarioId::QUANTUM_ATTACK;
    if (lower == "dense-urban-nlos" || lower == "dense-urban")
        return PqcScenarioId::DENSE_URBAN_NLOS;
    if (lower == "high-speed-handover" || lower == "high-speed")
        return PqcScenarioId::HIGH_SPEED_HANDOVER;
    if (lower == "core-bottleneck")
        return PqcScenarioId::CORE_BOTTLENECK;
    if (lower == "edge-backhaul-latency")
        return PqcScenarioId::EDGE_BACKHAUL_LATENCY;
    return PqcScenarioId::HYBRID_KYBER768_X25519;
}

const char*
ScenarioIdToString(PqcScenarioId id)
{
    switch (id)
    {
    case PqcScenarioId::BASELINE_ECC:
        return "baseline-ecc";
    case PqcScenarioId::KYBER512:
        return "kyber512";
    case PqcScenarioId::KYBER768:
        return "kyber768";
    case PqcScenarioId::KYBER1024:
        return "kyber1024";
    case PqcScenarioId::KYBER768_CACHED:
        return "kyber768-cached";
    case PqcScenarioId::HYBRID_KYBER768_X25519:
        return "hybrid-kyber768-x25519";
    case PqcScenarioId::HYBRID_KYBER768_X25519_CACHED:
        return "hybrid-kyber768-x25519-cached";
    case PqcScenarioId::QUANTUM_ATTACK:
        return "quantum-attack";
    case PqcScenarioId::DENSE_URBAN_NLOS:
        return "dense-urban-nlos";
    case PqcScenarioId::HIGH_SPEED_HANDOVER:
        return "high-speed-handover";
    case PqcScenarioId::CORE_BOTTLENECK:
        return "core-bottleneck";
    case PqcScenarioId::EDGE_BACKHAUL_LATENCY:
        return "edge-backhaul-latency";
    }
    return "hybrid-kyber768-x25519";
}

PqcScenarioHelper::PqcScenarioHelper()
{
}

PqcScenarioHelper::~PqcScenarioHelper()
{
}

void
PqcScenarioHelper::SetConfig(const PqcScenarioConfig& config)
{
    m_config = config;
}

const PqcScenarioConfig&
PqcScenarioHelper::GetConfig() const
{
    return m_config;
}

PqcScenarioHelper::ScenarioResult
PqcScenarioHelper::CreateFromScenarioId(PqcScenarioId id, uint32_t numUes)
{
    switch (id)
    {
    case PqcScenarioId::DENSE_URBAN_NLOS:
        m_config.nlosEnabled = true;
        m_config.urbanCanyon = true;
        return CreateDenseUrbanScenario((numUes + 6) / 7);
    case PqcScenarioId::HIGH_SPEED_HANDOVER:
        m_config.enableHandover = true;
        return CreateHighSpeedMobilityScenario(5, numUes, m_config.speed);
    case PqcScenarioId::CORE_BOTTLENECK:
        m_config.coreBottleneck = true;
        m_config.s1uLinkDelay = MilliSeconds(10);
        return CreateDenseUrbanScenario((numUes + 6) / 7);
    case PqcScenarioId::EDGE_BACKHAUL_LATENCY:
        return CreateDenseUrbanScenario((numUes + 6) / 7);
    case PqcScenarioId::BASELINE_ECC:
    default:
        if (numUes > 20)
        {
            return CreateDenseUrbanScenario((numUes + 6) / 7);
        }
        return CreateBaselineScenario(numUes);
    }
}

PqcScenarioHelper::ScenarioResult
PqcScenarioHelper::SetupNrStack(NodeContainer& gnbNodes,
                                 NodeContainer& ueNodes,
                                 double frequency,
                                 double bandwidth)
{
    ScenarioResult result;
    result.gnbNodes = gnbNodes;
    result.ueNodes = ueNodes;
    result.numGnbs = gnbNodes.GetN();
    result.numUes = ueNodes.GetN();

    Config::SetDefault("ns3::LteRlcUm::MaxTxBufferSize", UintegerValue(999999999));
    // Config::SetDefault("ns3::NrHelper::UseIdealRrc", BooleanValue(false)); // Not valid in 5G-LENA NrHelper

    // Create helpers
    result.epcHelper = CreateObject<NrPointToPointEpcHelper>();
    auto idealBeamformingHelper = CreateObject<IdealBeamformingHelper>();
    result.nrHelper = CreateObject<NrHelper>();

    result.nrHelper->SetBeamformingHelper(idealBeamformingHelper);
    result.nrHelper->SetEpcHelper(result.epcHelper);

    // Setup MEC Backhaul
    NodeContainer mecNode;
    mecNode.Create(1);
    PointToPointHelper p2pMec;
    p2pMec.SetDeviceAttribute("DataRate", DataRateValue(DataRate("10Gbps")));
    p2pMec.SetChannelAttribute("Delay", TimeValue(m_config.edgeBackhaulDelay));
    p2pMec.Install(result.epcHelper->GetPgwNode(), mecNode.Get(0));

    if (m_config.enableHandover || m_config.speed > 50.0)
    {
        // Handover algorithm API varies by NR module version; mobility stress still applies.
        NS_LOG_INFO("Handover scenario enabled (mobility + rekey); NR HO algorithm not wired in this build.");
    }

    // Spectrum configuration
    CcBwpCreator ccBwpCreator;
    CcBwpCreator::SimpleOperationBandConf bandConf(frequency,
                                                    bandwidth,
                                                    1,
                                                    BandwidthPartInfo::UMi_StreetCanyon);
    OperationBandInfo band = ccBwpCreator.CreateOperationBandContiguousCc(bandConf);

    Config::SetDefault("ns3::ThreeGppChannelModel::UpdatePeriod", TimeValue(MilliSeconds(0)));
    // result.nrHelper->SetChannelConditionModelAttribute("TypeId", StringValue("ns3::ThreeGppChannelConditionModel"));
    // result.nrHelper->SetChannelConditionModelAttribute("Scenario", StringValue("UMa-AV"));
    // result.nrHelper->SetPathlossModel("ns3::ThreeGppPropagationLossModel");
    result.nrHelper->SetPathlossAttribute("ShadowingEnabled", BooleanValue(m_config.nlosEnabled));
    if (m_config.urbanCanyon)
    {
        result.nrHelper->SetPathlossAttribute("ShadowingEnabled", BooleanValue(true));
        // MODELED: increased shadowing for urban canyon (ASSUMED)
        Config::SetDefault("ns3::ThreeGppPropagationLossModel::ShadowingStd",
                           DoubleValue(m_config.shadowingStdDb * 1.5));
    }
    else if (m_config.nlosEnabled)
    {
        Config::SetDefault("ns3::ThreeGppPropagationLossModel::ShadowingStd",
                           DoubleValue(m_config.shadowingStdDb));
    }
    result.nrHelper->InitializeOperationBand(&band);

    BandwidthPartInfoPtrVector allBwps = CcBwpCreator::GetAllBwps({band});

    idealBeamformingHelper->SetAttribute(
        "BeamformingMethod",
        TypeIdValue(DirectPathBeamforming::GetTypeId()));

    Time s1uDelay = m_config.coreBottleneck ? MilliSeconds(10) : m_config.s1uLinkDelay;
    result.epcHelper->SetAttribute("S1uLinkDelay", TimeValue(s1uDelay));

    // UE antenna config
    result.nrHelper->SetUeAntennaAttribute("NumRows", UintegerValue(2));
    result.nrHelper->SetUeAntennaAttribute("NumColumns", UintegerValue(4));
    result.nrHelper->SetUeAntennaAttribute(
        "AntennaElement",
        PointerValue(CreateObject<IsotropicAntennaModel>()));

    // gNB antenna config
    result.nrHelper->SetGnbAntennaAttribute("NumRows", UintegerValue(4));
    result.nrHelper->SetGnbAntennaAttribute("NumColumns", UintegerValue(8));
    result.nrHelper->SetGnbAntennaAttribute(
        "AntennaElement",
        PointerValue(CreateObject<IsotropicAntennaModel>()));

    // BWP manager
    result.nrHelper->SetGnbBwpManagerAlgorithmAttribute("NGBR_LOW_LAT_EMBB", UintegerValue(0));
    result.nrHelper->SetUeBwpManagerAlgorithmAttribute("NGBR_LOW_LAT_EMBB", UintegerValue(0));

    // Install NR stack (gNB Internet stack is installed internally by EpcHelper::AddEnb)
    result.gnbDevices = result.nrHelper->InstallGnbDevice(gnbNodes, allBwps);
    result.ueDevices = result.nrHelper->InstallUeDevice(ueNodes, allBwps);

    // Enable X2/Xn interfaces AFTER InstallGnbDevice (gNBs need Ipv4 from AddEnb first)
    for (uint32_t i = 0; i < gnbNodes.GetN(); ++i) {
        for (uint32_t j = i + 1; j < gnbNodes.GetN(); ++j) {
            result.epcHelper->AddX2Interface(gnbNodes.Get(i), gnbNodes.Get(j));
        }
    }

    // Assign random streams
    int64_t randomStream = 1;
    randomStream += result.nrHelper->AssignStreams(result.gnbDevices, randomStream);
    randomStream += result.nrHelper->AssignStreams(result.ueDevices, randomStream);

    // Configure gNB PHY
    for (uint32_t i = 0; i < result.gnbDevices.GetN(); ++i)
    {
        result.nrHelper->GetGnbPhy(result.gnbDevices.Get(i), 0)
            ->SetAttribute("Numerology", UintegerValue(1));
        result.nrHelper->GetGnbPhy(result.gnbDevices.Get(i), 0)
            ->SetAttribute("TxPower", DoubleValue(35.0));
    }

    // Finalize configs
    for (auto it = result.gnbDevices.Begin(); it != result.gnbDevices.End(); ++it)
    {
        DynamicCast<NrGnbNetDevice>(*it)->UpdateConfig();
    }
    for (auto it = result.ueDevices.Begin(); it != result.ueDevices.End(); ++it)
    {
        DynamicCast<NrUeNetDevice>(*it)->UpdateConfig();
    }

    // Internet stack on UEs — MUST be after InstallUeDevice (per NR examples)
    // Do NOT install on gnbNodes — EpcHelper::AddEnb already does it
    InternetStackHelper internet;
    internet.Install(ueNodes);

    auto ueIpIfaces = result.epcHelper->AssignUeIpv4Address(result.ueDevices);

    Ipv4StaticRoutingHelper routingHelper;
    for (uint32_t j = 0; j < ueNodes.GetN(); ++j)
    {
        auto ueRouting = routingHelper.GetStaticRouting(ueNodes.Get(j)->GetObject<Ipv4>());
        ueRouting->SetDefaultRoute(result.epcHelper->GetUeDefaultGatewayAddress(), 1);
    }

    // Attach UEs to closest gNB
    result.nrHelper->AttachToClosestEnb(result.ueDevices, result.gnbDevices);

    return result;
}

PqcScenarioHelper::ScenarioResult
PqcScenarioHelper::CreateDenseUrbanScenario(uint32_t numUesPerGnb,
                                              double isd,
                                              double frequency,
                                              double bandwidth)
{
    const uint32_t numGnbs = 7; // Hexagonal: 1 center + 6
    const double gnbHeight = 25.0;
    const double ueHeight = 1.5;

    NS_LOG_INFO("Creating Dense Urban Scenario: " << numGnbs << " gNBs, "
                << numUesPerGnb << " UEs/cell, ISD=" << isd << "m");

    NodeContainer gnbNodes;
    gnbNodes.Create(numGnbs);

    NodeContainer ueNodes;
    ueNodes.Create(numGnbs * numUesPerGnb);

    // gNB placement: hexagonal grid
    MobilityHelper gnbMobility;
    gnbMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");

    Ptr<ListPositionAllocator> gnbPositions = CreateObject<ListPositionAllocator>();
    gnbPositions->Add(Vector(0.0, 0.0, gnbHeight)); // Center cell

    for (uint32_t i = 0; i < 6; ++i)
    {
        double angle = 2.0 * M_PI * i / 6.0;
        double x = isd * std::cos(angle);
        double y = isd * std::sin(angle);
        gnbPositions->Add(Vector(x, y, gnbHeight));
    }

    gnbMobility.SetPositionAllocator(gnbPositions);
    gnbMobility.Install(gnbNodes);

    // UE placement: Gauss-Markov mobility
    MobilityHelper ueMobility;
    ueMobility.SetMobilityModel("ns3::GaussMarkovMobilityModel",
        "Bounds", BoxValue(Box(-5000, 5000, -5000, 5000, 80, 80)),
        "TimeStep", TimeValue(Seconds(0.5)),
        "Alpha", DoubleValue(0.85),
        "MeanVelocity", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=" +
                                    std::to_string(m_config.speed) + "]"),
        "MeanDirection", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=6.283185307]"),
        "MeanPitch", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=0.0]"));

    Ptr<ListPositionAllocator> uePositions = CreateObject<ListPositionAllocator>();
    Ptr<UniformRandomVariable> rng = CreateObject<UniformRandomVariable>();

    for (uint32_t g = 0; g < numGnbs; ++g)
    {
        auto gnbMob = gnbNodes.Get(g)->GetObject<MobilityModel>();
        Vector gnbPos = gnbMob->GetPosition();

        for (uint32_t u = 0; u < numUesPerGnb; ++u)
        {
            double r = rng->GetValue(10.0, isd / 2.0);
            double theta = rng->GetValue(0, 2.0 * M_PI);
            double x = gnbPos.x + r * std::cos(theta);
            double y = gnbPos.y + r * std::sin(theta);
            uePositions->Add(Vector(x, y, 80.0)); // Initial position at altitude 80m
        }
    }

    ueMobility.SetPositionAllocator(uePositions);
    ueMobility.Install(ueNodes);

    return SetupNrStack(gnbNodes, ueNodes, frequency, bandwidth);
}

PqcScenarioHelper::ScenarioResult
PqcScenarioHelper::CreateHighSpeedMobilityScenario(uint32_t numGnbs,
                                                     uint32_t numUes,
                                                     double speed,
                                                     double gnbSpacing)
{
    const double gnbHeight = 25.0;
    const double ueHeight = 1.5;
    const double trackOffset = 50.0; // Track is 50m from gNB line

    NS_LOG_INFO("Creating High-Speed Mobility Scenario: " << numGnbs
                << " gNBs, " << numUes << " UEs, speed=" << speed << " m/s ("
                << speed * 3.6 << " km/h)");

    NodeContainer gnbNodes;
    gnbNodes.Create(numGnbs);

    NodeContainer ueNodes;
    ueNodes.Create(numUes);

    // gNB placement: linear along corridor
    MobilityHelper gnbMobility;
    gnbMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");

    Ptr<ListPositionAllocator> gnbPositions = CreateObject<ListPositionAllocator>();
    for (uint32_t i = 0; i < numGnbs; ++i)
    {
        gnbPositions->Add(Vector(i * gnbSpacing, 0.0, gnbHeight));
    }
    gnbMobility.SetPositionAllocator(gnbPositions);
    gnbMobility.Install(gnbNodes);

    // UE placement: constant velocity along the track
    MobilityHelper ueMobility;
    ueMobility.SetMobilityModel("ns3::ConstantVelocityMobilityModel");

    // Start UEs behind the first gNB
    Ptr<ListPositionAllocator> uePositions = CreateObject<ListPositionAllocator>();
    for (uint32_t i = 0; i < numUes; ++i)
    {
        double startX = -200.0 - (i * 10.0); // Staggered start
        uePositions->Add(Vector(startX, trackOffset, ueHeight));
    }
    ueMobility.SetPositionAllocator(uePositions);
    ueMobility.Install(ueNodes);

    // Set velocity for each UE
    for (uint32_t i = 0; i < numUes; ++i)
    {
        auto mob = ueNodes.Get(i)->GetObject<ConstantVelocityMobilityModel>();
        mob->SetVelocity(Vector(speed, 0.0, 0.0)); // Moving east at high speed
    }

    return SetupNrStack(gnbNodes, ueNodes, 3.5e9, 20e6);
}

PqcScenarioHelper::ScenarioResult
PqcScenarioHelper::CreateBaselineScenario(uint32_t numUes)
{
    NS_LOG_INFO("Creating Baseline Scenario: 1 gNB, " << numUes << " UEs");

    NodeContainer gnbNodes;
    gnbNodes.Create(1);

    NodeContainer ueNodes;
    ueNodes.Create(numUes);

    // gNB at center
    MobilityHelper gnbMobility;
    gnbMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    Ptr<ListPositionAllocator> gnbPos = CreateObject<ListPositionAllocator>();
    gnbPos->Add(Vector(0.0, 0.0, 10.0));
    gnbMobility.SetPositionAllocator(gnbPos);
    gnbMobility.Install(gnbNodes);

    // UEs in a circle around gNB
    MobilityHelper ueMobility;
    ueMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    Ptr<ListPositionAllocator> uePos = CreateObject<ListPositionAllocator>();

    for (uint32_t i = 0; i < numUes; ++i)
    {
        double angle = 2.0 * M_PI * i / numUes;
        double x = 20.0 * std::cos(angle);
        double y = 20.0 * std::sin(angle);
        uePos->Add(Vector(x, y, 1.5));
    }
    ueMobility.SetPositionAllocator(uePos);
    ueMobility.Install(ueNodes);

    return SetupNrStack(gnbNodes, ueNodes, 3.5e9, 20e6);
}

} // namespace pqc
} // namespace ns3
