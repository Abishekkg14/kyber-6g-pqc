/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#ifndef PQC_ENERGY_MODEL_H
#define PQC_ENERGY_MODEL_H

#include "hardware-profile.h"

#include "ns3/nstime.h"

namespace ns3
{
namespace pqc
{

/**
 * \brief Multi-component energy accounting for PQC workloads.
 *
 * MODELED — not measured on physical drones. See docs/simulation-methodology.md.
 */
struct PqcEnergyBreakdown
{
    double cryptoComputeMj{0};
    double txMj{0};
    double rxMj{0};
    double idleMj{0};
    double memoryMj{0};

    double TotalMj() const
    {
        return cryptoComputeMj + txMj + rxMj + idleMj + memoryMj;
    }
};

class PqcEnergyModel
{
  public:
    explicit PqcEnergyModel(const HardwareProfile& profile);

    void SetBatteryWh(double wh);
    void SetTxPowerW(double w) { m_txPowerW = w; }
    void SetRxPowerW(double w) { m_rxPowerW = w; }

    PqcEnergyBreakdown ComputeHandshakeEnergy(Time cryptoTime,
                                              uint32_t memoryBytes,
                                              Time txTime,
                                              Time rxTime,
                                              Time idleTime) const;

    double EstimateBatteryLifeMinutes(const PqcEnergyBreakdown& total,
                                      double simDurationSeconds) const;

    const HardwareProfile& GetProfile() const { return m_profile; }

  private:
    HardwareProfile m_profile;
    double m_batteryWh{74.0};
    double m_txPowerW{0.52};  ///< HITL-measured RF transmit power
    double m_rxPowerW{0.16};  ///< HITL-measured RF receive power
};

} // namespace pqc
} // namespace ns3

#endif // PQC_ENERGY_MODEL_H
