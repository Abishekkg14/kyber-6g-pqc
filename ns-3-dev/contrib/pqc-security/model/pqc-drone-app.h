/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#ifndef PQC_DRONE_APP_H
#define PQC_DRONE_APP_H

#include "aes-gcm-cipher.h"
#include "pqc-metrics-collector.h"

#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ipv4-address.h"
#include "ns3/ptr.h"
#include "ns3/socket.h"
#include "ns3/traced-callback.h"

#include <vector>

namespace ns3
{
namespace pqc
{

/**
 * \brief Drone Application for telemetry and coordination in the swarm.
 *
 * Simulates a UDP-based mission-critical application. It uses AesGcmCipher
 * to encrypt outward telemetry and command packets before sending them over
 * the socket. On the receiving end, it decrypts and calculates End-to-End
 * Application Latency, passing metrics to the PqcMetricsCollector.
 */
class PqcDroneApp : public Application
{
  public:
    enum PacketType : uint8_t
    {
        TELEMETRY = 0,
        NAVIGATION_UPDATE = 1,
        COMMAND = 2
    };

    static TypeId GetTypeId();

    PqcDroneApp();
    ~PqcDroneApp() override;

    /**
     * \brief Setup the application parameters.
     * \param isCommander True if this drone is the swarm leader.
     * \param peerAddress IP address of the peer drone (or multicast address)
     * \param peerPort UDP port of the peer
     * \param cipher The AES-GCM cipher object for this drone
     * \param metrics The global metrics collector
     */
    void Setup(bool isCommander, Ipv4Address peerAddress, uint16_t peerPort, 
               Ptr<AesGcmCipher> cipher, Ptr<PqcMetricsCollector> metrics);

  protected:
    void DoDispose() override;

  private:
    void StartApplication() override;
    void StopApplication() override;

    /// Send a telemetry packet
    void SendTelemetry();

    /// Send a navigation update (Commander only)
    void SendNavigationUpdate();

    /// Send a mission command (Commander only)
    void SendCommand();

    /// Create and transmit an encrypted packet
    void TransmitPacket(PacketType type, uint32_t payloadSize);

    /// Handle incoming packets
    void HandleRead(Ptr<Socket> socket);

    bool m_isCommander;         //!< Role of the drone in the swarm 
    uint32_t m_packetSize;      //!< Base size of application payload
    Time m_interval;            //!< Time interval between sending telemetry
    Ipv4Address m_peerAddress;  //!< Destination address
    uint16_t m_peerPort;        //!< Destination port

    Ptr<Socket> m_socket;       //!< UDP socket
    EventId m_sendTelemetryEvent; //!< Event for next telemetry transmission
    EventId m_sendNavEvent;       //!< Event for next navigation transmission
    EventId m_sendCmdEvent;       //!< Event for random command transmission
    uint32_t m_packetsSent;     //!< Counter for sent packets

    Ptr<AesGcmCipher> m_cipher;              //!< Encryption engine
    Ptr<PqcMetricsCollector> m_metrics;      //!< Metrics collector
};

} // namespace pqc
} // namespace ns3

#endif // PQC_DRONE_APP_H
