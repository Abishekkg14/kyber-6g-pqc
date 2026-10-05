import ScrollReveal from '../components/ScrollReveal'
import Figure from '../components/Figure'

const STEPS = [
  {
    title: 'Full handshake (1.5 round trips)',
    text: 'The UAV sends a signed ClientHello with a one-time X25519 share and a one-time ML-KEM-1024 public key. The ground station answers with its share, the ML-KEM ciphertext, its signature over the whole transcript and a Finished value; the UAV confirms with its own.',
    detail: 'PRK = HKDF-Extract(salt = SHA-256(transcript), ML-KEM secret || X25519 secret)',
  },
  {
    title: '1-RTT Cached RapidRekey',
    text: 'A new session from the secret the last one left behind: one request, one answer, no public-key operation. It moves the keys forward and cannot be walked backwards, but it does not heal a session whose secret leaked.',
    detail: 'PRK = HKDF-Extract(salt = SHA-256(request, nonce, new id), resumption secret)',
  },
  {
    title: 'PQ ratchet',
    text: 'A fresh ML-KEM-1024 and X25519 exchange inside the running session, mixed with the old master secret. This is the step that heals: after it, an attacker who had read out the old secret and only listened is locked out again.',
    detail: 'PRK = HKDF-Extract(salt = TH, ML-KEM secret || X25519 secret || old master)',
  },
  {
    title: 'Records',
    text: 'Every datagram is one AES-256-GCM record. Each stream, direction and epoch has its own key from a one-way chain; the sequence number is the nonce and is never reused; a window refuses replays.',
    detail: 'nonce = 0^32 || sequence number   ·   associated data = the whole header',
  },
  {
    title: 'Stored files',
    text: 'A photo, a recording or an audio clip gets a random content key, wrapped under a key that needs both of the ground station\'s recording keys (ML-KEM-1024 and X25519), and the UAV\'s ML-DSA-87 signature over every byte.',
    detail: 'KEK = HKDF(salt = SHA-256(header, ciphertext, one-time key), ML-KEM secret || X25519 secret)',
  },
]

export default function CryptoWorkflow() {
  return (
    <section id="crypto" className="section" aria-label="Protocol">
      <div className="section-inner">
        <ScrollReveal>
          <span className="section-label">Protocol</span>
          <h2>How keys are made, moved on and healed</h2>
          <p className="section-desc">
            Three ways to get a new session, from the most thorough to the cheapest, and two formats for what is
            sent and what is stored. In all of them the post-quantum algorithms make, wrap and sign keys;
            AES-256-GCM encrypts the data.
          </p>
        </ScrollReveal>
        <div className="workflow-steps">
          {STEPS.map((s, i) => (
            <ScrollReveal key={i} delay={(i % 3) + 1}>
              <div className="workflow-step">
                <div className="step-number">{i + 1}</div>
                <div className="step-content">
                  <h3>{s.title}</h3>
                  <p>{s.text}</p>
                  <div className="step-detail mono">{s.detail}</div>
                </div>
              </div>
            </ScrollReveal>
          ))}
        </div>
        <ScrollReveal>
          <Figure name="fig03_handshake" caption="The full handshake: what each message carries and what is signed." />
        </ScrollReveal>
        <ScrollReveal>
          <Figure name="fig13_rekey_flows" caption="The message flows of the 1-RTT Cached RapidRekey and of the PQ ratchet." />
        </ScrollReveal>
        <ScrollReveal>
          <Figure name="fig04_key_schedule" caption="The key schedule: from the two shared secrets to a key per stream, direction and epoch." />
        </ScrollReveal>
      </div>
    </section>
  )
}
