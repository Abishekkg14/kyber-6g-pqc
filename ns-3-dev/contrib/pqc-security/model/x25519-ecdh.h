/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#ifndef X25519_ECDH_H
#define X25519_ECDH_H

#include "ns3/nstime.h"
#include "ns3/object.h"
#include "ns3/random-variable-stream.h"
#include "ns3/traced-callback.h"
#include "ns3/type-id.h"

#include <cstdint>
#include <vector>

namespace ns3
{
namespace pqc
{

/**
 * \brief Simulated X25519 Elliptic Curve Diffie-Hellman key exchange.
 *
 * Generates correct-sized (32-byte) key material and injects
 * benchmark-derived computation delays. Used as the classical
 * component of the hybrid KEM.
 */
class X25519Ecdh : public Object
{
  public:
    static constexpr uint32_t PUBLIC_KEY_SIZE = 32;  ///< X25519 public key
    static constexpr uint32_t SECRET_KEY_SIZE = 32;  ///< X25519 private key
    static constexpr uint32_t SHARED_SECRET_SIZE = 32;

    struct KeyPair
    {
        std::vector<uint8_t> publicKey;  // 32 bytes
        std::vector<uint8_t> secretKey;  // 32 bytes
        Time generationTime;
    };

    struct SharedSecretResult
    {
        std::vector<uint8_t> sharedSecret; // 32 bytes
        Time computeTime;
    };

    static TypeId GetTypeId();

    X25519Ecdh();
    ~X25519Ecdh() override;

    /**
     * \brief Generate an X25519 key pair.
     */
    KeyPair KeyGen();

    /**
     * \brief Compute shared secret from our secret key and peer's public key.
     */
    SharedSecretResult ComputeSharedSecret(const std::vector<uint8_t>& mySecretKey,
                                            const std::vector<uint8_t>& peerPublicKey);

    TracedCallback<Time> m_keyGenTrace;
    TracedCallback<Time> m_dhTrace;

  private:
    Time m_keyGenTime;
    Time m_dhTime;
    Ptr<UniformRandomVariable> m_rng;

    std::vector<uint8_t> GenerateRandomBytes(uint32_t size);
};

} // namespace pqc
} // namespace ns3

#endif // X25519_ECDH_H
