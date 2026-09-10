/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#ifndef QUANTUM_ATTACKER_H
#define QUANTUM_ATTACKER_H

#include "pqc-session-keys.h"

#include "ns3/application.h"
#include "ns3/net-device.h"
#include "ns3/nstime.h"
#include "ns3/packet.h"
#include "ns3/traced-callback.h"
#include "ns3/type-id.h"

#include <map>
#include <vector>

namespace ns3
{
namespace pqc
{

/**
 * \brief Simulated "store-and-decrypt" quantum adversary.
 *
 * Models the HNDL (Harvest Now, Decrypt Later) attack:
 *   Phase 1 (PASSIVE_CAPTURE): Promiscuously captures all wireless
 *     frames, storing RRC handshake messages and encrypted PDCP PDUs.
 *   Phase 2 (QUANTUM_DECRYPT): After simulation, simulates a quantum
 *     computer breaking classical ECDH (X25519) and attempts to
 *     derive session keys and decrypt captured traffic.
 *
 * Expected results:
 *   - ECC-only baseline: Attacker decrypts 100% of traffic
 *   - Hybrid PQC (ECDH+Kyber): Attacker decrypts 0% of traffic
 *     (Kyber's lattice-based security remains intact)
 *
 * This proves the PQC implementation prevents retroactive decryption.
 */
class QuantumAttacker : public Application
{
  public:
    enum Mode
    {
        PASSIVE_CAPTURE = 0,  ///< Recording all traffic
        QUANTUM_DECRYPT = 1   ///< Attempting decryption
    };

    /// A captured wireless frame
    struct CapturedPacket
    {
        Time captureTime;
        uint32_t packetSize;
        std::vector<uint8_t> payload;
        uint64_t sourceImsi;
    };

    /// A captured RRC handshake
    struct CapturedHandshake
    {
        PqcRrcIePayload requestPayload;  // UE's public keys
        PqcRrcIePayload setupPayload;    // gNB's ciphertext
        bool isHybrid;                   // Whether Kyber was used
        Time captureTime;
    };

    /// Report from the decryption attempt
    struct DecryptionReport
    {
        uint32_t totalCapturedPackets;
        uint32_t totalCapturedHandshakes;
        uint32_t classicalKeysRecovered;   // ECDH keys broken by quantum
        uint32_t pqcKeysRecovered;         // Kyber keys (should be 0)
        uint32_t packetsDecrypted;
        uint32_t packetsFailedDecrypt;
        double decryptionSuccessRate;      // 0.0 for PQC, 1.0 for ECC-only
        std::string summary;
    };

    static TypeId GetTypeId();

    QuantumAttacker();
    ~QuantumAttacker() override;

    /**
     * \brief Promiscuous packet capture callback.
     *
     * Connected to the wireless channel to capture all frames.
     */
    void PromiscuousSniff(Ptr<const Packet> packet);

    /**
     * \brief Record a captured RRC handshake (from trace source).
     */
    void CaptureHandshake(uint64_t imsi, const CapturedHandshake& hs);

    /**
     * \brief Attempt to decrypt all captured traffic.
     *
     * Simulates a quantum computer:
     *   - Breaks all X25519 ECDH keys → recovers ECDH shared secret
     *   - Cannot break Kyber-768 lattice → fails to recover Kyber secret
     *   - For hybrid KEM: combined key requires BOTH → attacker fails
     *   - For ECC-only: ECDH alone suffices → attacker succeeds
     *
     * \return DecryptionReport with statistics.
     */
    DecryptionReport AttemptRetroactiveDecryption();

    /**
     * \brief Get the total number of captured packets.
     */
    uint32_t GetCapturedPacketCount() const;

    /**
     * \brief Get the current mode.
     */
    Mode GetMode() const;

    // Trace sources
    TracedCallback<uint32_t> m_packetCapturedTrace;
    TracedCallback<double> m_decryptionRateTrace; // Final success rate

  protected:
    void StartApplication() override;
    void StopApplication() override;

  private:
    Mode m_mode;
    bool m_captureEnabled;

    // Captured data
    std::vector<CapturedPacket> m_capturedTraffic;
    std::map<uint64_t, CapturedHandshake> m_capturedHandshakes; // IMSI → handshake

    // Configuration
    uint32_t m_maxCapturePackets; // Limit memory usage
};

} // namespace pqc
} // namespace ns3

#endif // QUANTUM_ATTACKER_H
