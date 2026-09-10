/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#include "pqc-energy-model.h"

#include "ns3/log.h"

namespace ns3
{
namespace pqc
{

NS_LOG_COMPONENT_DEFINE("PqcEnergyModel");

PqcEnergyModel::PqcEnergyModel(const HardwareProfile& profile)
    : m_profile(profile)
{
}

void
PqcEnergyModel::SetBatteryWh(double wh)
{
    m_batteryWh = wh;
}

PqcEnergyBreakdown
PqcEnergyModel::ComputeHandshakeEnergy(Time cryptoTime,
                                       uint32_t memoryBytes,
                                       Time txTime,
                                       Time rxTime,
                                       Time idleTime) const
{
    PqcEnergyBreakdown e;
    double cryptoSec = cryptoTime.GetSeconds();
    double txSec = txTime.GetSeconds();
    double rxSec = rxTime.GetSeconds();
    double idleSec = idleTime.GetSeconds();

    // MODELED — power × time (millijoules = watts × seconds × 1000)
    e.cryptoComputeMj = m_profile.cpuPowerW * cryptoSec * 1000.0;
    e.txMj = m_txPowerW * txSec * 1000.0;
    e.rxMj = m_rxPowerW * rxSec * 1000.0;
    e.idleMj = m_profile.idlePowerW * idleSec * 1000.0;
    // Memory: ~0.5 pJ/bit access scaled by profile (ASSUMED)
    e.memoryMj = (memoryBytes * 8.0 * 0.5e-12) * m_profile.memoryOverheadFactor * 1e9;

    return e;
}

double
PqcEnergyModel::EstimateBatteryLifeMinutes(const PqcEnergyBreakdown& total,
                                             double simDurationSeconds) const
{
    if (simDurationSeconds <= 0.0 || total.TotalMj() <= 0.0)
    {
        return 0.0;
    }
    double batteryMj = m_batteryWh * 3.6e6; // Wh -> mJ
    double rateMjPerSec = total.TotalMj() / simDurationSeconds;
    if (rateMjPerSec <= 0.0)
    {
        return 0.0;
    }
    // MODELED projection — not measured flight time
    return (batteryMj / rateMjPerSec) / 60.0;
}

} // namespace pqc
} // namespace ns3
