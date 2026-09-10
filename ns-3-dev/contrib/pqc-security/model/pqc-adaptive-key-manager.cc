/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#include "pqc-adaptive-key-manager.h"
#include "ns3/log.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"
#include <algorithm>

namespace ns3
{
namespace pqc
{

NS_LOG_COMPONENT_DEFINE("PqcAdaptiveKeyManager");
NS_OBJECT_ENSURE_REGISTERED(PqcAdaptiveKeyManager);

TypeId
PqcAdaptiveKeyManager::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::pqc::PqcAdaptiveKeyManager")
            .SetParent<Object>()
            .SetGroupName("PqcSecurity")
            .AddConstructor<PqcAdaptiveKeyManager>()
            .AddAttribute("BaseRekeyInterval",
                          "Frequency of rekeying when stationary.",
                          TimeValue(Seconds(10.0)),
                          MakeTimeAccessor(&PqcAdaptiveKeyManager::m_baseRekeyInterval),
                          MakeTimeChecker())
            .AddAttribute("SpeedThreshold",
                          "Velocity (m/s) where cache optimization becomes aggressive.",
                          DoubleValue(15.0),
                          MakeDoubleAccessor(&PqcAdaptiveKeyManager::m_speedThreshold),
                          MakeDoubleChecker<double>())
            .AddAttribute("MinRekeyInterval",
                          "Minimum time forced between handshakes.",
                          TimeValue(Seconds(1.0)),
                          MakeTimeAccessor(&PqcAdaptiveKeyManager::m_minRekeyInterval),
                          MakeTimeChecker());
    return tid;
}

PqcAdaptiveKeyManager::PqcAdaptiveKeyManager()
{
}

PqcAdaptiveKeyManager::~PqcAdaptiveKeyManager()
{
}

Time
PqcAdaptiveKeyManager::CalculateRekeyInterval(double speedMetersPerSecond) const
{
    // If we're moving fast, extend the interval proportionally to avoid extreme PQC overhead
    // For every multiple of m_speedThreshold, we increase the duration by 50%
    if (speedMetersPerSecond <= m_speedThreshold)
    {
        return m_baseRekeyInterval;
    }

    double ratio = speedMetersPerSecond / m_speedThreshold;
    double multiplier = 1.0 + (ratio * 0.5); 
    
    Time optimal = Time::FromDouble(m_baseRekeyInterval.GetSeconds() * multiplier, Time::S);
    return optimal;
}

bool
PqcAdaptiveKeyManager::RequiresHandshake(Time timeSinceLastHandshake, double speedMetersPerSecond) const
{
    Time maxAllowed = CalculateRekeyInterval(speedMetersPerSecond);
    
    // Safety limit: if we haven't hit the strict minimum, never force a rekey.
    if (timeSinceLastHandshake < m_minRekeyInterval)
    {
        return false;
    }
    
    bool needsRekey = (timeSinceLastHandshake >= maxAllowed);
    
    if (needsRekey) {
        NS_LOG_DEBUG("AdaptiveManager: Forcing Kyber Rekey. Time Elapsed: " 
                     << timeSinceLastHandshake.As(Time::S) 
                     << ", Speed: " << speedMetersPerSecond);
    } else {
        NS_LOG_DEBUG("AdaptiveManager: Skipping Kyber Rekey (Using Cache). Time Elapsed: " 
                     << timeSinceLastHandshake.As(Time::S) 
                     << ", Max Allowed: " << maxAllowed.As(Time::S));
    }
    
    return needsRekey;
}

} // namespace pqc
} // namespace ns3
