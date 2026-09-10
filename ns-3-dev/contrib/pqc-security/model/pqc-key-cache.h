/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#ifndef PQC_KEY_CACHE_H
#define PQC_KEY_CACHE_H

#include "ns3/nstime.h"
#include "ns3/object.h"
#include "ns3/type-id.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace ns3
{
namespace pqc
{

/**
 * \brief Mobility-aware PQC session key cache with TTL and revocation.
 *
 * Simulation model — not a production key store.
 */
class PqcKeyCache : public Object
{
  public:
    struct CacheEntry
    {
        uint64_t keyId{0};
        std::vector<uint8_t> combinedSecret;
        Time createdAt;
        Time ttl;
        uint32_t mobilityHash{0};
        bool revoked{false};
        uint64_t nonceCounter{0};
    };

    enum class LookupResult
    {
        HIT,
        MISS,
        STALE,
        REVOKED,
        REPLAY
    };

    static TypeId GetTypeId();

    PqcKeyCache();
    ~PqcKeyCache() override;

    void SetEnabled(bool enabled);
    void SetDefaultTtl(Time ttl);
    void SetRevocationEnabled(bool enabled);

    void Store(uint32_t ueIndex,
               const std::vector<uint8_t>& combinedSecret,
               uint32_t mobilityHash);
    LookupResult Lookup(uint32_t ueIndex,
                        uint32_t mobilityHash,
                        std::vector<uint8_t>& outSecret);
    void Revoke(uint32_t ueIndex);
    void Purge(uint32_t ueIndex);

    bool ValidateNonce(uint32_t ueIndex, uint64_t nonce);

    double GetHitRate() const;
    uint32_t GetStaleKeyEvents() const { return m_staleKeyEvents; }
    uint32_t GetRevokedReuseAttempts() const { return m_revokedReuseAttempts; }
    uint32_t GetReplayRejections() const { return m_replayRejections; }

  private:
    bool m_enabled{true};
    bool m_revocationEnabled{true};
    Time m_defaultTtl;
    std::map<uint32_t, CacheEntry> m_entries;
    uint32_t m_hits{0};
    uint32_t m_misses{0};
    uint32_t m_staleKeyEvents{0};
    uint32_t m_revokedReuseAttempts{0};
    uint32_t m_replayRejections{0};
    uint64_t m_nextKeyId{1};
};

} // namespace pqc
} // namespace ns3

#endif // PQC_KEY_CACHE_H
