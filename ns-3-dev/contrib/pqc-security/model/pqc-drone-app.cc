/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#include "pqc-drone-app.h"

#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/inet-socket-address.h"
#include "ns3/packet.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/uinteger.h"
#include "ns3/seq-ts-header.h"

namespace ns3
{
namespace pqc
{

NS_LOG_COMPONENT_DEFINE("PqcDroneApp");
NS_OBJECT_ENSURE_REGISTERED(PqcDroneApp);

TypeId
PqcDroneApp::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::pqc::PqcDroneApp")
            .SetParent<Application>()
            .SetGroupName("PqcSecurity")
            .AddConstructor<PqcDroneApp>()
            .AddAttribute("PacketSize",
                          "Size of application payload (bytes)",
                          UintegerValue(512),
                          MakeUintegerAccessor(&PqcDroneApp::m_packetSize),
                          MakeUintegerChecker<uint32_t>())
            .AddAttribute("Interval",
                          "Time between packet transmissions",
                          TimeValue(MilliSeconds(20)), // 50 Hz telemetry
                          MakeTimeAccessor(&PqcDroneApp::m_interval),
                          MakeTimeChecker());
    return tid;
}

PqcDroneApp::PqcDroneApp()
    : m_isCommander(false),
      m_packetSize(512),
      m_interval(MilliSeconds(20)),
      m_peerPort(0),
      m_socket(nullptr),
      m_packetsSent(0),
      m_cipher(nullptr),
      m_metrics(nullptr)
{
}

PqcDroneApp::~PqcDroneApp()
{
}

void
PqcDroneApp::DoDispose()
{
    m_socket = nullptr;
    m_cipher = nullptr;
    m_metrics = nullptr;
    Application::DoDispose();
}

void
PqcDroneApp::Setup(bool isCommander, Ipv4Address peerAddress, uint16_t peerPort, 
                   Ptr<AesGcmCipher> cipher, Ptr<PqcMetricsCollector> metrics)
{
    m_isCommander = isCommander;
    m_peerAddress = peerAddress;
    m_peerPort = peerPort;
    m_cipher = cipher;
    m_metrics = metrics;
}

void
PqcDroneApp::StartApplication()
{
    // Create socket
    if (!m_socket)
    {
        TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
        m_socket = Socket::CreateSocket(GetNode(), tid);
        InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), m_peerPort);
        if (m_socket->Bind(local) == -1)
        {
            NS_FATAL_ERROR("Failed to bind socket");
        }
        m_socket->Connect(InetSocketAddress(m_peerAddress, m_peerPort));
    }

    m_socket->SetRecvCallback(MakeCallback(&PqcDroneApp::HandleRead, this));

    m_packetsSent = 0;
    
    // Everyone sends telemetry
    m_sendTelemetryEvent = Simulator::Schedule(Seconds(0.0), &PqcDroneApp::SendTelemetry, this);
    
    // Commander broadcasts navigation updates and commands
    if (m_isCommander) {
        m_sendNavEvent = Simulator::Schedule(MilliSeconds(200), &PqcDroneApp::SendNavigationUpdate, this);
        m_sendCmdEvent = Simulator::Schedule(Seconds(1.5), &PqcDroneApp::SendCommand, this);
    }
}

void
PqcDroneApp::StopApplication()
{
    if (m_sendTelemetryEvent.IsPending()) Simulator::Cancel(m_sendTelemetryEvent);
    if (m_sendNavEvent.IsPending()) Simulator::Cancel(m_sendNavEvent);
    if (m_sendCmdEvent.IsPending()) Simulator::Cancel(m_sendCmdEvent);

    if (m_socket)
    {
        m_socket->Close();
        m_socket->SetRecvCallback(MakeNullCallback<void, Ptr<Socket>>());
    }
}

void
PqcDroneApp::SendTelemetry()
{
    TransmitPacket(TELEMETRY, m_packetSize);
    m_sendTelemetryEvent = Simulator::Schedule(m_interval, &PqcDroneApp::SendTelemetry, this);
}

void
PqcDroneApp::SendNavigationUpdate()
{
    // Nav updates are smaller (Coordinates, velocity vector)
    TransmitPacket(NAVIGATION_UPDATE, 64);
    m_sendNavEvent = Simulator::Schedule(MilliSeconds(200), &PqcDroneApp::SendNavigationUpdate, this);
}

void
PqcDroneApp::SendCommand()
{
    // High-priority swarm commands (formation change, target assignment)
    TransmitPacket(COMMAND, 128);
    // Commands happen pseudo-randomly
    m_sendCmdEvent = Simulator::Schedule(Seconds(2.0), &PqcDroneApp::SendCommand, this);
}

void
PqcDroneApp::TransmitPacket(PacketType type, uint32_t payloadSize)
{
    // 1. Create Application Payload with Sequence and internal Type tracking
    SeqTsHeader seqTs;
    seqTs.SetSeq(m_packetsSent);

    // We need at least the sequence header size and 1 byte for our type enum
    if (payloadSize < seqTs.GetSerializedSize() + 1)
    {
        payloadSize = seqTs.GetSerializedSize() + 1;
    }
    
    // We package the payload directly. Dummy bytes represent real mission data.
    std::vector<uint8_t> dummyPlaintext(payloadSize, 0);
    dummyPlaintext[0] = static_cast<uint8_t>(type);
    
    // 2. Encrypt using AES-GCM
    if (m_cipher && m_cipher->HasKeys())
    {
        AesGcmCipher::EncryptResult result = m_cipher->Encrypt(dummyPlaintext);
        
        Ptr<Packet> p = Create<Packet>(result.ciphertext.size());
        p->AddHeader(seqTs);
        
        m_socket->Send(p);
        NS_LOG_DEBUG("DroneApp: Sent Encrypted Packet " << m_packetsSent << " type " << type << " size " << p->GetSize());
    }
    else
    {
        NS_LOG_WARN("DroneApp: Sending Unencrypted Packet " << m_packetsSent << " (Waiting for keys)");
        Ptr<Packet> p = Create<Packet>(payloadSize);
        p->AddHeader(seqTs);
        m_socket->Send(p);
    }

    if (m_metrics)
    {
        m_metrics->RecordPacketSent();
    }
    m_packetsSent++;
}

void
PqcDroneApp::HandleRead(Ptr<Socket> socket)
{
    Ptr<Packet> packet;
    Address from;
    while ((packet = socket->RecvFrom(from)))
    {
        if (packet->GetSize() == 0)
        {
            break; // EOF
        }

        SeqTsHeader seqTs;
        packet->RemoveHeader(seqTs);

        // Calculate latency
        Time e2eLatency = Simulator::Now() - seqTs.GetTs();

        // Simulated Byte Vector Extraction for Decryption
        std::vector<uint8_t> dummyCiphertext(packet->GetSize(), 0);

        if (m_cipher && m_cipher->HasKeys())
        {
            AesGcmCipher::DecryptResult result = m_cipher->Decrypt(dummyCiphertext);
            
            if (!result.authenticated)
            {
                if (m_metrics) m_metrics->RecordPacketLoss();
                NS_LOG_WARN("DroneApp: Dropped Packet due to Decryption Failure.");
                continue;
            }

            NS_LOG_DEBUG("DroneApp: Received & Decrypted Packet. Latency: " << e2eLatency.As(Time::MS));
            
            if (m_metrics)
            {
                m_metrics->RecordE2eApplicationLatency(e2eLatency);
                // Assume throughput bytes are the actual payload (excluding GCM tag/nonce overhead added by network)
                m_metrics->RecordThroughputBytes(result.plaintext.size()); 
                m_metrics->RecordPacketReceived();
            }
        }
        else
        {
            NS_LOG_WARN("DroneApp: Received packet but no keys installed to decrypt!");
            if (m_metrics)
            {
                m_metrics->RecordE2eApplicationLatency(e2eLatency);
                m_metrics->RecordThroughputBytes(packet->GetSize());
                m_metrics->RecordPacketReceived();
            }
        }
    }
}

} // namespace pqc
} // namespace ns3
