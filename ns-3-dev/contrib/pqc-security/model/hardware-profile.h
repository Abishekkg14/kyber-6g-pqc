/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#ifndef HARDWARE_PROFILE_H
#define HARDWARE_PROFILE_H

#include <cstdint>
#include <string>

namespace ns3
{
namespace pqc
{

/**
 * \brief Edge/drone hardware profiles for crypto timing and energy modeling.
 *
 * All power and scale values are ASSUMED — not measured on target hardware.
 * See docs/simulation-methodology.md for provenance.
 */
enum class HardwareProfileId
{
    CORTEX_A55 = 0,
    PIXHAWK_CLASS = 1,
    JETSON_NANO = 2,
    JETSON_ORIN = 3,
    EDGE_SERVER = 4
};

struct HardwareProfile
{
    HardwareProfileId id;
    const char* name;
    double cryptoTimingScale;   ///< Multiplier on baseline Kyber/X25519 timings
    double cpuPowerW;           ///< Active crypto CPU power (ASSUMED)
    double idlePowerW;          ///< Idle platform power (ASSUMED)
    double memoryOverheadFactor;///< DRAM energy scaling for large PQ payloads
    uint32_t maxParallelOps;    ///< Max concurrent crypto ops (1 = sequential only)
};

HardwareProfile GetHardwareProfile(HardwareProfileId id);
HardwareProfile GetHardwareProfileByName(const std::string& name);
HardwareProfileId ParseHardwareProfileName(const std::string& name);

} // namespace pqc
} // namespace ns3

#endif // HARDWARE_PROFILE_H
