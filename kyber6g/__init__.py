"""Kyber-6G multimodal secure HITL link.

Post-quantum-secured session establishment (ML-KEM-1024 + X25519 hybrid,
ML-DSA-87 authentication) followed by symmetric authenticated encryption
(AES-256-GCM) of telemetry, images, video and control traffic.
"""

PROTOCOL_VERSION = 1
