/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#include "pqc-key-cache.h"

#include "ns3/boolean.h"
#include "ns3/log.h"
#include "ns3/simulator.h"

namespace ns3
{
namespace pqc
{

NS_LOG_COMPONENT_DEFINE("PqcKeyCache");
NS_OBJECT_ENSURE_REGISTERED(PqcKeyCache);

TypeId
PqcKeyCache::GetTypeId()
{
    static TypeId tid = TypeId("ns3::pqc::PqcKeyCache")
                            .SetParent<Object>()
                            .SetGroupName("PqcSecurity")
                            .AddConstructor<PqcKeyCache>()
                            .AddAttribute("Enabled",
                                          "Enable mobility-aware key cache",
                                          BooleanValue(true),
                                          MakeBooleanAccessor(&PqcKeyCache::m_enabled),
                                          MakeBooleanChecker())
                            .AddAttribute("DefaultTtl",
                                          "Default cache entry TTL",
                                          TimeValue(Seconds(300)),
                                          MakeTimeAccessor(&PqcKeyCache::m_defaultTtl),
                                          MakeTimeChecker());
    return tid;
}

PqcKeyCache::PqcKeyCache()
    : m_defaultTtl(Seconds(300))
{
}

PqcKeyCache::~PqcKeyCache()
{
}

void
PqcKeyCache::SetEnabled(bool enabled)
{
    m_enabled = enabled;
}

void
PqcKeyCache::SetDefaultTtl(Time ttl)
{
    m_defaultTtl = ttl;
}

void
PqcKeyCache::SetRevocationEnabled(bool enabled)
{
    m_revocationEnabled = enabled;
}

void
PqcKeyCache::Store(uint32_t ueIndex,
                   const std::vector<uint8_t>& combinedSecret,
                   uint32_t mobilityHash)
{
    if (!m_enabled)
    {
        return;
    }
    CacheEntry entry;
    entry.keyId = m_nextKeyId++;
    entry.combinedSecret = combinedSecret;
    entry.createdAt = Simulator::Now();
    entry.ttl = m_defaultTtl;
    entry.mobilityHash = mobilityHash;
    entry.revoked = false;
    entry.nonceCounter = 0;
    m_entries[ueIndex] = entry;
    NS_LOG_DEBUG("PqcKeyCache: stored key for UE " << ueIndex);
}

PqcKeyCache::LookupResult
PqcKeyCache::Lookup(uint32_t ueIndex,
                    uint32_t mobilityHash,
                    std::vector<uint8_t>& outSecret)
{
    if (!m_enabled)
    {
        ++m_misses;
        return LookupResult::MISS;
    }

    auto it = m_entries.find(ueIndex);
    if (it == m_entries.end())
    {
        ++m_misses;
        return LookupResult::MISS;
    }

    auto& entry = it->second;

    if (m_revocationEnabled && entry.revoked)
    {
        ++m_revokedReuseAttempts;
        return LookupResult::REVOKED;
    }

    Time age = Simulator::Now() - entry.createdAt;
    if (age > entry.ttl)
    {
        ++m_staleKeyEvents;
        return LookupResult::STALE;
    }

    if (entry.mobilityHash != mobilityHash)
    {
        ++m_staleKeyEvents;
        return LookupResult::STALE;
    }

    outSecret = entry.combinedSecret;
    ++m_hits;
    return LookupResult::HIT;
}

void
PqcKeyCache::Revoke(uint32_t ueIndex)
{
    auto it = m_entries.find(ueIndex);
    if (it != m_entries.end())
    {
        it->second.revoked = true;
        NS_LOG_INFO("PqcKeyCache: revoked key for UE " << ueIndex);
    }
}

void
PqcKeyCache::Purge(uint32_t ueIndex)
{
    m_entries.erase(ueIndex);
    NS_LOG_INFO("PqcKeyCache: purged cache for UE " << ueIndex);
}

bool
PqcKeyCache::ValidateNonce(uint32_t ueIndex, uint64_t nonce)
{
    auto it = m_entries.find(ueIndex);
    if (it == m_entries.end())
    {
        return true;
    }
    if (nonce <= it->second.nonceCounter)
    {
        ++m_replayRejections;
        return false;
    }
    it->second.nonceCounter = nonce;
    return true;
}

double
PqcKeyCache::GetHitRate() const
{
    uint32_t total = m_hits + m_misses;
    if (total == 0)
    {
        return 0.0;
    }
    return static_cast<double>(m_hits) / static_cast<double>(total);
}

} // namespace pqc
} // namespace ns3
