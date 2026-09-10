/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#ifndef AES_GCM_CIPHER_H
#define AES_GCM_CIPHER_H

#include "pqc-session-keys.h"

#include "ns3/nstime.h"
#include "ns3/object.h"
#include "ns3/traced-callback.h"
#include "ns3/type-id.h"

#include <cstdint>
#include <vector>

namespace ns3
{
namespace pqc
{

/**
 * \brief Simulated AES-256-GCM authenticated encryption for PDCP payload.
 *
 * Simulates the per-packet overhead and computational cost of
 * AES-256-GCM encryption/decryption. Adds realistic overhead:
 *   - 12-byte nonce (prepended)
 *   - 16-byte GCM authentication tag (appended)
 *   - Total per-packet overhead: 28 bytes
 *
 * Does NOT perform actual encryption — packets remain readable
 * in simulation traces for debugging/analysis. The overhead
 * is accurately represented in packet sizes.
 */
class AesGcmCipher : public Object
{
  public:
    static constexpr uint32_t NONCE_SIZE = 12;   ///< AES-GCM nonce/IV
    static constexpr uint32_t TAG_SIZE = 16;     ///< GCM authentication tag
    static constexpr uint32_t KEY_SIZE = 32;     ///< AES-256 key
    static constexpr uint32_t OVERHEAD = NONCE_SIZE + TAG_SIZE; // 28 bytes

    struct EncryptResult
    {
        std::vector<uint8_t> ciphertext; // plaintext + nonce (12B) + tag (16B)
        Time encryptTime;
        uint32_t overhead; // 28 bytes
    };

    struct DecryptResult
    {
        std::vector<uint8_t> plaintext;
        bool authenticated; // GCM tag verification
        Time decryptTime;
    };

    static TypeId GetTypeId();

    AesGcmCipher();
    ~AesGcmCipher() override;

    /**
     * \brief Install session keys for encryption/decryption.
     */
    void InstallKeys(const PqcSessionKeys& keys);

    /**
     * \brief Encrypt a plaintext payload (simulated).
     *
     * The "ciphertext" is the original plaintext with 28 bytes of
     * overhead prepended/appended. No actual encryption occurs.
     */
    EncryptResult Encrypt(const std::vector<uint8_t>& plaintext);

    /**
     * \brief Decrypt a ciphertext payload (simulated).
     *
     * Strips the 28-byte overhead and returns the original payload.
     */
    DecryptResult Decrypt(const std::vector<uint8_t>& ciphertext);

    /**
     * \brief Check if keys have been installed.
     */
    bool HasKeys() const;

    // Trace sources
    TracedCallback<Time> m_encryptTrace;
    TracedCallback<Time> m_decryptTrace;
    TracedCallback<uint32_t, uint32_t> m_overheadTrace; // plaintext_size, encrypted_size

  private:
    PqcSessionKeys m_keys;
    bool m_keysInstalled{false};

    // Timing: AES-256-GCM on modern hardware is very fast (~1 cycle/byte)
    Time m_encryptTimePerByte;
    Time m_decryptTimePerByte;
    Time m_encryptFixedOverhead; // setup cost per packet
    Time m_decryptFixedOverhead;
};

} // namespace pqc
} // namespace ns3

#endif // AES_GCM_CIPHER_H
