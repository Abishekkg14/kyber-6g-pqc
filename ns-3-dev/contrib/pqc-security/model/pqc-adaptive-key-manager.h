/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#ifndef PQC_ADAPTIVE_KEY_MANAGER_H
#define PQC_ADAPTIVE_KEY_MANAGER_H

#include "ns3/nstime.h"
#include "ns3/object.h"

namespace ns3
{
namespace pqc
{

/**
 * \brief Balances PQC security overhead by dynamically adjusting rekey intervals.
 * 
 * At high speeds (e.g., UAV formation flights), forcing a full CRYSTALS-Kyber
 * handshake on every tiny cell handover causes severe congestion and key exhaustion.
 * This manager scales the key refresh interval inversely with drone mobility, utilizing
 * Pre-Shared Key (PSK) / session key caching for rapid handovers when moving fast.
 */
class PqcAdaptiveKeyManager : public Object
{
  public:
    static TypeId GetTypeId();

    PqcAdaptiveKeyManager();
    ~PqcAdaptiveKeyManager() override;

    /**
     * \brief Calculate the optimal time until the next full Kyber Key Exchange.
     * \param speedMetersPerSecond Current speed of the drone.
     * \return Standard duration until next mandatory rekey.
     */
    Time CalculateRekeyInterval(double speedMetersPerSecond) const;

    /**
     * \brief Determine if a handover should trigger a full handshake or use a cached key.
     * \param timeSinceLastHandshake Duration since the last full Kyber exchange.
     * \param speedMetersPerSecond Current speed.
     * \return True if full PQC handshake required, false if safe to use cached PSK.
     */
    bool RequiresHandshake(Time timeSinceLastHandshake, double speedMetersPerSecond) const;

  private:
    Time m_baseRekeyInterval; //!< Base rekey interval for stationary nodes
    double m_speedThreshold;  //!< Velocity above which aggressive caching begins (m/s)
    Time m_minRekeyInterval;  //!< Absolute shortest allowed interval
};

} // namespace pqc
} // namespace ns3

#endif // PQC_ADAPTIVE_KEY_MANAGER_H
