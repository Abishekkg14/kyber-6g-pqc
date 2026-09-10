/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#ifndef PQC_SCENARIO_HELPER_H
#define PQC_SCENARIO_HELPER_H

#include "ns3/mobility-helper.h"
#include "ns3/net-device-container.h"
#include "ns3/node-container.h"
#include "ns3/nr-helper.h"
#include "ns3/nr-point-to-point-epc-helper.h"
#include "ns3/nstime.h"
#include "ns3/position-allocator.h"

#include <cstdint>
#include <string>

namespace ns3
{
namespace pqc
{

/**
 * \brief Named experiment scenarios for PQC evaluation matrix.
 */
enum class PqcScenarioId
{
    BASELINE_ECC,
    KYBER512,
    KYBER768,
    KYBER1024,
    KYBER768_CACHED,
    HYBRID_KYBER768_X25519,
    HYBRID_KYBER768_X25519_CACHED,
    QUANTUM_ATTACK,
    DENSE_URBAN_NLOS,
    HIGH_SPEED_HANDOVER,
    CORE_BOTTLENECK,
    EDGE_BACKHAUL_LATENCY,
    BAND_6G_THZ,             ///< Projected 6G THz band analysis (140 GHz)
    BAND_6G_THZ_BASELINE,
    BAND_6G_XWING_HYBRID,
    BAND_6G_DORA_ROUTING,
    BAND_6G_MOSAIC_SWARM,
    ABLATION_A1_NO_CSIDH,
    ABLATION_A2_PURE_MLKEM,
    ABLATION_A3_MM1_QUEUE,
    ABLATION_A4_ZRP_ROUTING,
    ABLATION_A5_DSRP_ROUTING,
    ABLATION_A6_UNMASKED_SHA3,
    ABLATION_A7_NO_CVQKD,
    ABLATION_A8_NO_EMULSION
};

PqcScenarioId ParseScenarioId(const std::string& name);
const char* ScenarioIdToString(PqcScenarioId id);

/**
 * \brief Radio/backhaul scenario configuration (all CLI-configurable).
 */
struct PqcScenarioConfig
{
    bool nlosEnabled{false};
    bool urbanCanyon{false};
    double speed{25.0};
    Time edgeBackhaulDelay{MilliSeconds(2)};
    Time s1uLinkDelay{MilliSeconds(0)};
    bool enableHandover{false};
    bool coreBottleneck{false};
    double shadowingStdDb{4.0};
    double lossRate{0.0};          ///< Packet loss rate [0.0–1.0] for lossy channel experiments
    double frequency6gHz{140e9};   ///< 6G THz center frequency (default 140 GHz)
    double bandwidth6gHz{400e6};   ///< 6G THz bandwidth (default 400 MHz)
};

/**
 * \brief Pre-configured network scenarios for PQC experiments.
 */
class PqcScenarioHelper
{
  public:
    struct ScenarioResult
    {
        NodeContainer gnbNodes;
        NodeContainer ueNodes;
        NetDeviceContainer gnbDevices;
        NetDeviceContainer ueDevices;
        Ptr<NrPointToPointEpcHelper> epcHelper;
        Ptr<NrHelper> nrHelper;
        uint32_t numGnbs;
        uint32_t numUes;
    };

    PqcScenarioHelper();
    ~PqcScenarioHelper();

    void SetConfig(const PqcScenarioConfig& config);
    const PqcScenarioConfig& GetConfig() const;

    ScenarioResult CreateDenseUrbanScenario(uint32_t numUesPerGnb = 15,
                                             double isd = 200.0,
                                             double frequency = 3.5e9,
                                             double bandwidth = 20e6);

    ScenarioResult CreateHighSpeedMobilityScenario(uint32_t numGnbs = 5,
                                                     uint32_t numUes = 10,
                                                     double speed = 120.0,
                                                     double gnbSpacing = 200.0);

    ScenarioResult CreateBaselineScenario(uint32_t numUes = 2);

    /**
     * \brief Create a projected 6G THz band scenario.
     *
     * Uses 140 GHz center frequency, 400 MHz bandwidth, Numerology 4 (240 kHz SCS).
     * NOTE: 6G THz is beyond NS-3's validated channel models — labeled as
     * projected analysis with extrapolated UMi-StreetCanyon model.
     */
    ScenarioResult CreateSixGBandScenario(uint32_t numUes = 2);

    ScenarioResult CreateFromScenarioId(PqcScenarioId id, uint32_t numUes);

  private:
    PqcScenarioConfig m_config;

    ScenarioResult SetupNrStack(NodeContainer& gnbNodes,
                                NodeContainer& ueNodes,
                                double frequency,
                                double bandwidth);
};

} // namespace pqc
} // namespace ns3

#endif // PQC_SCENARIO_HELPER_H
