/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#include "hardware-profile.h"

#include "ns3/log.h"

#include <algorithm>
#include <cctype>

namespace ns3
{
namespace pqc
{

NS_LOG_COMPONENT_DEFINE("HardwareProfile");

// ASSUMED for all except RPI4_CORTEX_A72 (HITL-calibrated).
// See docs/simulation-methodology.md for provenance.
static const HardwareProfile PROFILES[] = {
    {HardwareProfileId::CORTEX_A55, "cortex-a55", 1.8, 2.0, 0.5, 1.2, 1},
    {HardwareProfileId::PIXHAWK_CLASS, "pixhawk-class", 3.5, 1.5, 0.3, 1.0, 1},
    {HardwareProfileId::JETSON_NANO, "jetson-nano", 0.6, 5.0, 1.0, 1.5, 2},
    {HardwareProfileId::JETSON_ORIN, "jetson-orin", 0.25, 15.0, 2.0, 2.0, 4},
    {HardwareProfileId::EDGE_SERVER, "edge-server", 0.1, 45.0, 8.0, 3.0, 8},
    // MEASURED on Raspberry Pi 4 Model B 2GB (BCM2711 Cortex-A72 @ 1.5 GHz)
    // HITL-calibrated: cpuPowerW=5.0W, idlePowerW=1.0W, dual-core crypto bound
    {HardwareProfileId::RPI4_CORTEX_A72, "rpi4-cortex-a72", 1.0, 5.0, 1.0, 1.3, 2},
};

HardwareProfile
GetHardwareProfile(HardwareProfileId id)
{
    for (const auto& p : PROFILES)
    {
        if (p.id == id)
        {
            return p;
        }
    }
    NS_LOG_WARN("Unknown hardware profile id, defaulting to rpi4-cortex-a72");
    return PROFILES[5]; // RPI4_CORTEX_A72
}

HardwareProfile
GetHardwareProfileByName(const std::string& name)
{
    return GetHardwareProfile(ParseHardwareProfileName(name));
}

HardwareProfileId
ParseHardwareProfileName(const std::string& name)
{
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower == "cortex-a55" || lower == "cortex_a55")
        return HardwareProfileId::CORTEX_A55;
    if (lower == "pixhawk-class" || lower == "pixhawk_class" || lower == "pixhawk")
        return HardwareProfileId::PIXHAWK_CLASS;
    if (lower == "jetson-nano" || lower == "jetson_nano")
        return HardwareProfileId::JETSON_NANO;
    if (lower == "jetson-orin" || lower == "jetson_orin")
        return HardwareProfileId::JETSON_ORIN;
    if (lower == "edge-server" || lower == "edge_server")
        return HardwareProfileId::EDGE_SERVER;
    if (lower == "rpi4-cortex-a72" || lower == "rpi4" || lower == "rpi4_cortex_a72"
        || lower == "raspberry-pi-4" || lower == "cortex-a72")
        return HardwareProfileId::RPI4_CORTEX_A72;
    NS_LOG_WARN("Unknown hardware profile '" << name << "', defaulting to rpi4-cortex-a72");
    return HardwareProfileId::RPI4_CORTEX_A72;
}

} // namespace pqc
} // namespace ns3
