/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#ifndef PQC_PDCP_LAYER_H
#define PQC_PDCP_LAYER_H

#include "aes-gcm-cipher.h"
#include "pqc-session-keys.h"

#include "ns3/nstime.h"
#include "ns3/object.h"
#include "ns3/packet.h"
#include "ns3/traced-callback.h"
#include "ns3/type-id.h"

#include <cstdint>

namespace ns3
{
namespace pqc
{

/**
 * \brief PQC-aware PDCP layer that encrypts/decrypts user-plane data.
 *
 * This class intercepts packets at the PDCP layer and applies
 * AES-256-GCM encryption using session keys derived from the
 * hybrid KEM handshake. It adds per-packet overhead (28 bytes)
 * and records encryption/decryption latency for metrics.
 *
 * Integration: Installed by PqcSecurityHelper on each UE/gNB bearer.
 * Connected to the NR PDCP layer via trace source callbacks.
 *
 * The layer operates in two modes:
 *   - TRANSPARENT: Keys not yet established, packets pass through
 *   - ENCRYPTED: Keys installed, all packets are encrypted
 */
class PqcPdcpLayer : public Object
{
  public:
    enum Mode
    {
        TRANSPARENT = 0, ///< No encryption (keys not yet established)
        ENCRYPTED = 1    ///< AES-256-GCM encryption active
    };

    static TypeId GetTypeId();

    PqcPdcpLayer();
    ~PqcPdcpLayer() override;

    /**
     * \brief Install session keys derived from hybrid KEM.
     * Transitions mode from TRANSPARENT to ENCRYPTED.
     */
    void InstallSessionKeys(const PqcSessionKeys& keys);

    /**
     * \brief Update session keys (e.g., during handover re-keying).
     * Increments keyGeneration counter for forward secrecy tracking.
     */
    void UpdateSessionKeys(const PqcSessionKeys& newKeys);

    /**
     * \brief Process an outgoing PDCP SDU (encrypt before transmission).
     *
     * Called on the transmit path. Adds GCM nonce+tag overhead.
     * \param packet The packet to process.
     * \return The encrypted packet (with overhead) and processing time.
     */
    Ptr<Packet> ProcessTxSdu(Ptr<Packet> packet);

    /**
     * \brief Process an incoming PDCP PDU (decrypt after reception).
     *
     * Called on the receive path. Strips GCM nonce+tag overhead.
     * \param packet The received encrypted packet.
     * \return The decrypted packet and processing time.
     */
    Ptr<Packet> ProcessRxPdu(Ptr<Packet> packet);

    /**
     * \brief Get current operating mode.
     */
    Mode GetMode() const;

    /**
     * \brief Get the per-packet overhead in bytes.
     */
    uint32_t GetPerPacketOverhead() const;

    /**
     * \brief Get total bytes of overhead added across all packets.
     */
    uint64_t GetTotalOverheadBytes() const;

    /**
     * \brief Get count of packets processed.
     */
    uint64_t GetPacketsProcessed() const;

    // ── Trace sources for metrics ──
    TracedCallback<uint32_t, uint32_t> m_txOverheadTrace; // original_size, encrypted_size
    TracedCallback<uint32_t, uint32_t> m_rxOverheadTrace; // encrypted_size, decrypted_size
    TracedCallback<Time> m_encryptLatencyTrace;
    TracedCallback<Time> m_decryptLatencyTrace;
    TracedCallback<uint32_t> m_keyGenerationTrace; // keyGeneration counter

  private:
    Mode m_mode;
    PqcSessionKeys m_sessionKeys;
    Ptr<AesGcmCipher> m_cipher;

    // Counters
    uint64_t m_totalOverheadBytes{0};
    uint64_t m_packetsEncrypted{0};
    uint64_t m_packetsDecrypted{0};
};

} // namespace pqc
} // namespace ns3

#endif // PQC_PDCP_LAYER_H
