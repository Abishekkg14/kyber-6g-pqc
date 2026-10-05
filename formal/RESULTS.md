# Machine-checked protocol models: results

Written by `formal/run.py` on 2026-10-05 14:04:53 IST with Proverif 2.05. Cryptographic protocol verifier, by Bruno Blanchet, Vincent Cheval, and Marc Sylvestre.

**100 of 100 claims proved; 77 of 77 attacks found where one must exist** (46 runs, 177 queries, 29.7 s).

A claim is a query that must hold (`true`). The other queries must NOT hold (`false`): they ask the same thing with the decisive scheme broken or the decisive key stolen, or whether the protocol can finish at all. They show that each model can fail. Attackers: `classical` = breaks nothing; `shor` = X25519 broken; `mlkem` = ML-KEM broken; `both` = X25519 and ML-KEM broken.


## `handshake.pv`

full handshake; both signing keys are given to the attacker afterwards (phase 1); a second pinned UAV is the attacker's.

| attacker | query (ProVerif's wording) | result | expected |
|---|---|---|---|
| classical | `not attacker_p1(secretU[])` | true | true |
| classical | `not attacker_p1(secretG[])` | true | true |
| classical | `inj-event(GcsAccept(idU,idG,s,k)) ==> inj-event(UavAccept(idU,idG,s,k))` | true | true |
| classical | `inj-event(UavAccept(u,gid_1,s,k)) ==> inj-event(GcsRunning(u,gid_1,s,k))` | true | true |
| classical | `not event(GcsAccept(idU,idG,s,k))` | false | false |
| shor | `not attacker_p1(secretU[])` | true | true |
| shor | `not attacker_p1(secretG[])` | true | true |
| shor | `inj-event(GcsAccept(idU,idG,s,k)) ==> inj-event(UavAccept(idU,idG,s,k))` | true | true |
| shor | `inj-event(UavAccept(u,gid_1,s,k)) ==> inj-event(GcsRunning(u,gid_1,s,k))` | true | true |
| shor | `not event(GcsAccept(idU,idG,s,k))` | false | false |
| mlkem | `not attacker_p1(secretU[])` | true | true |
| mlkem | `not attacker_p1(secretG[])` | true | true |
| mlkem | `inj-event(GcsAccept(idU,idG,s,k)) ==> inj-event(UavAccept(idU,idG,s,k))` | true | true |
| mlkem | `inj-event(UavAccept(u,gid_1,s,k)) ==> inj-event(GcsRunning(u,gid_1,s,k))` | true | true |
| mlkem | `not event(GcsAccept(idU,idG,s,k))` | false | false |
| both | `not attacker_p1(secretU[])` | false | false |
| both | `not attacker_p1(secretG[])` | false | false |
| both | `inj-event(GcsAccept(idU,idG,s,k)) ==> inj-event(UavAccept(idU,idG,s,k))` | false | false |
| both | `inj-event(UavAccept(u,gid_1,s,k)) ==> inj-event(GcsRunning(u,gid_1,s,k))` | true | true |
| both | `not event(GcsAccept(idU,idG,s,k))` | false | false |

## `cached_rekey.pv` with `leak_none.pvl`

1-RTT Cached RapidRekey from a secret resumption secret.

| attacker | query (ProVerif's wording) | result | expected |
|---|---|---|---|
| classical | `not attacker(secretU1[])` | true | true |
| classical | `not attacker(secretG1[])` | true | true |
| classical | `inj-event(GcsRekeyed(sid0,s,k_3)) ==> inj-event(UavRekeyed(sid0,s,k_3))` | true | true |
| classical | `event(UavRekeyed(sid0,s,k_3)) ==> event(GcsRunning(sid0,s,k_3))` | true | true |
| classical | `not event(GcsRekeyed(sid0,s,k_3))` | false | false |
| shor | `not attacker(secretU1[])` | true | true |
| shor | `not attacker(secretG1[])` | true | true |
| shor | `inj-event(GcsRekeyed(sid0,s,k_3)) ==> inj-event(UavRekeyed(sid0,s,k_3))` | true | true |
| shor | `event(UavRekeyed(sid0,s,k_3)) ==> event(GcsRunning(sid0,s,k_3))` | true | true |
| shor | `not event(GcsRekeyed(sid0,s,k_3))` | false | false |
| mlkem | `not attacker(secretU1[])` | true | true |
| mlkem | `not attacker(secretG1[])` | true | true |
| mlkem | `inj-event(GcsRekeyed(sid0,s,k_3)) ==> inj-event(UavRekeyed(sid0,s,k_3))` | true | true |
| mlkem | `event(UavRekeyed(sid0,s,k_3)) ==> event(GcsRunning(sid0,s,k_3))` | true | true |
| mlkem | `not event(GcsRekeyed(sid0,s,k_3))` | false | false |
| both | `not attacker(secretU1[])` | true | true |
| both | `not attacker(secretG1[])` | true | true |
| both | `inj-event(GcsRekeyed(sid0,s,k_3)) ==> inj-event(UavRekeyed(sid0,s,k_3))` | true | true |
| both | `event(UavRekeyed(sid0,s,k_3)) ==> event(GcsRunning(sid0,s,k_3))` | true | true |
| both | `not event(GcsRekeyed(sid0,s,k_3))` | false | false |

## `cached_rekey.pv` with `leak_next.pvl`

... and the next resumption secret leaks afterwards (the chain is one-way).

| attacker | query (ProVerif's wording) | result | expected |
|---|---|---|---|
| classical | `not attacker_p1(secretU1[])` | true | true |
| classical | `not attacker_p1(secretG1[])` | true | true |
| classical | `inj-event(GcsRekeyed(sid0,s,k_3)) ==> inj-event(UavRekeyed(sid0,s,k_3))` | true | true |
| classical | `event(UavRekeyed(sid0,s,k_3)) ==> event(GcsRunning(sid0,s,k_3))` | true | true |
| classical | `not event(GcsRekeyed(sid0,s,k_3))` | false | false |
| shor | `not attacker_p1(secretU1[])` | true | true |
| shor | `not attacker_p1(secretG1[])` | true | true |
| shor | `inj-event(GcsRekeyed(sid0,s,k_3)) ==> inj-event(UavRekeyed(sid0,s,k_3))` | true | true |
| shor | `event(UavRekeyed(sid0,s,k_3)) ==> event(GcsRunning(sid0,s,k_3))` | true | true |
| shor | `not event(GcsRekeyed(sid0,s,k_3))` | false | false |
| mlkem | `not attacker_p1(secretU1[])` | true | true |
| mlkem | `not attacker_p1(secretG1[])` | true | true |
| mlkem | `inj-event(GcsRekeyed(sid0,s,k_3)) ==> inj-event(UavRekeyed(sid0,s,k_3))` | true | true |
| mlkem | `event(UavRekeyed(sid0,s,k_3)) ==> event(GcsRunning(sid0,s,k_3))` | true | true |
| mlkem | `not event(GcsRekeyed(sid0,s,k_3))` | false | false |
| both | `not attacker_p1(secretU1[])` | true | true |
| both | `not attacker_p1(secretG1[])` | true | true |
| both | `inj-event(GcsRekeyed(sid0,s,k_3)) ==> inj-event(UavRekeyed(sid0,s,k_3))` | true | true |
| both | `event(UavRekeyed(sid0,s,k_3)) ==> event(GcsRunning(sid0,s,k_3))` | true | true |
| both | `not event(GcsRekeyed(sid0,s,k_3))` | false | false |

## `cached_rekey.pv` with `leak_before.pvl`

... but the resumption secret had leaked BEFORE: a cached rekey does not heal (expected to fail).

| attacker | query (ProVerif's wording) | result | expected |
|---|---|---|---|
| classical | `not attacker(secretU1[])` | false | false |
| classical | `not attacker(secretG1[])` | false | false |
| classical | `inj-event(GcsRekeyed(sid0,s,k_3)) ==> inj-event(UavRekeyed(sid0,s,k_3))` | false | false |
| classical | `event(UavRekeyed(sid0,s,k_3)) ==> event(GcsRunning(sid0,s,k_3))` | false | false |
| classical | `not event(GcsRekeyed(sid0,s,k_3))` | false | false |
| shor | `not attacker(secretU1[])` | false | false |
| shor | `not attacker(secretG1[])` | false | false |
| shor | `inj-event(GcsRekeyed(sid0,s,k_3)) ==> inj-event(UavRekeyed(sid0,s,k_3))` | false | false |
| shor | `event(UavRekeyed(sid0,s,k_3)) ==> event(GcsRunning(sid0,s,k_3))` | false | false |
| shor | `not event(GcsRekeyed(sid0,s,k_3))` | false | false |
| mlkem | `not attacker(secretU1[])` | false | false |
| mlkem | `not attacker(secretG1[])` | false | false |
| mlkem | `inj-event(GcsRekeyed(sid0,s,k_3)) ==> inj-event(UavRekeyed(sid0,s,k_3))` | false | false |
| mlkem | `event(UavRekeyed(sid0,s,k_3)) ==> event(GcsRunning(sid0,s,k_3))` | false | false |
| mlkem | `not event(GcsRekeyed(sid0,s,k_3))` | false | false |
| both | `not attacker(secretU1[])` | false | false |
| both | `not attacker(secretG1[])` | false | false |
| both | `inj-event(GcsRekeyed(sid0,s,k_3)) ==> inj-event(UavRekeyed(sid0,s,k_3))` | false | false |
| both | `event(UavRekeyed(sid0,s,k_3)) ==> event(GcsRunning(sid0,s,k_3))` | false | false |
| both | `not event(GcsRekeyed(sid0,s,k_3))` | false | false |

## `pq_ratchet.pv` with `leak_none.pvl`

PQ ratchet inside a healthy session.

| attacker | query (ProVerif's wording) | result | expected |
|---|---|---|---|
| classical | `not attacker(secretU2[])` | true | true |
| classical | `not attacker(secretG2[])` | true | true |
| classical | `event(UavRatcheted(sid0,s,k_2)) ==> event(GcsRatcheted(sid0,s,k_2))` | true | true |
| classical | `not event(UavRatcheted(sid0,s,k_2))` | false | false |
| shor | `not attacker(secretU2[])` | true | true |
| shor | `not attacker(secretG2[])` | true | true |
| shor | `event(UavRatcheted(sid0,s,k_2)) ==> event(GcsRatcheted(sid0,s,k_2))` | true | true |
| shor | `not event(UavRatcheted(sid0,s,k_2))` | false | false |
| mlkem | `not attacker(secretU2[])` | true | true |
| mlkem | `not attacker(secretG2[])` | true | true |
| mlkem | `event(UavRatcheted(sid0,s,k_2)) ==> event(GcsRatcheted(sid0,s,k_2))` | true | true |
| mlkem | `not event(UavRatcheted(sid0,s,k_2))` | false | false |
| both | `not attacker(secretU2[])` | true | true |
| both | `not attacker(secretG2[])` | true | true |
| both | `event(UavRatcheted(sid0,s,k_2)) ==> event(GcsRatcheted(sid0,s,k_2))` | true | true |
| both | `not event(UavRatcheted(sid0,s,k_2))` | false | false |

## `pq_ratchet.pv` with `leak_next.pvl`

... and the OLD master secret leaks afterwards.

| attacker | query (ProVerif's wording) | result | expected |
|---|---|---|---|
| classical | `not attacker_p1(secretU2[])` | true | true |
| classical | `not attacker_p1(secretG2[])` | true | true |
| classical | `event(UavRatcheted(sid0,s,k_2)) ==> event(GcsRatcheted(sid0,s,k_2))` | true | true |
| classical | `not event(UavRatcheted(sid0,s,k_2))` | false | false |
| shor | `not attacker_p1(secretU2[])` | true | true |
| shor | `not attacker_p1(secretG2[])` | true | true |
| shor | `event(UavRatcheted(sid0,s,k_2)) ==> event(GcsRatcheted(sid0,s,k_2))` | true | true |
| shor | `not event(UavRatcheted(sid0,s,k_2))` | false | false |
| mlkem | `not attacker_p1(secretU2[])` | true | true |
| mlkem | `not attacker_p1(secretG2[])` | true | true |
| mlkem | `event(UavRatcheted(sid0,s,k_2)) ==> event(GcsRatcheted(sid0,s,k_2))` | true | true |
| mlkem | `not event(UavRatcheted(sid0,s,k_2))` | false | false |
| both | `not attacker_p1(secretU2[])` | false | false |
| both | `not attacker_p1(secretG2[])` | false | false |
| both | `event(UavRatcheted(sid0,s,k_2)) ==> event(GcsRatcheted(sid0,s,k_2))` | true | true |
| both | `not event(UavRatcheted(sid0,s,k_2))` | false | false |

## `pq_ratchet_active.pv`

... the old master secret leaked before and the attacker is ACTIVE during the ratchet (expected to fail).

| attacker | query (ProVerif's wording) | result | expected |
|---|---|---|---|
| classical | `not attacker(secretU2[])` | false | false |
| classical | `event(UavRatcheted(sid0,s,k)) ==> event(GcsRatcheted(sid0,s,k))` | false | false |

## `pq_ratchet_passive.pv`

PQ ratchet after the old master secret leaked, attacker only LISTENS: the session heals.

| attacker | query (ProVerif's wording) | result | expected |
|---|---|---|---|
| classical | `not attacker(secretU2[])` | true | true |
| classical | `not attacker(secretG2[])` | true | true |
| classical | `not event(UavRatcheted(sid0,s,k))` | false | false |
| shor | `not attacker(secretU2[])` | true | true |
| shor | `not attacker(secretG2[])` | true | true |
| shor | `not event(UavRatcheted(sid0,s,k))` | false | false |
| mlkem | `not attacker(secretU2[])` | true | true |
| mlkem | `not attacker(secretG2[])` | true | true |
| mlkem | `not event(UavRatcheted(sid0,s,k))` | false | false |
| both | `not attacker(secretU2[])` | false | false |
| both | `not attacker(secretG2[])` | false | false |
| both | `not event(UavRatcheted(sid0,s,k))` | false | false |

## `sealed_file.pv` with `file_leak_none.pvl`

stored photo / recording / audio clip.

| attacker | query (ProVerif's wording) | result | expected |
|---|---|---|---|
| classical | `not attacker(fileSecret[])` | true | true |
| classical | `event(GcsOpened(f,d)) ==> event(UavSealed(f,d))` | true | true |
| classical | `not event(GcsOpened(f,d))` | false | false |
| shor | `not attacker(fileSecret[])` | true | true |
| shor | `event(GcsOpened(f,d)) ==> event(UavSealed(f,d))` | true | true |
| shor | `not event(GcsOpened(f,d))` | false | false |
| mlkem | `not attacker(fileSecret[])` | true | true |
| mlkem | `event(GcsOpened(f,d)) ==> event(UavSealed(f,d))` | true | true |
| mlkem | `not event(GcsOpened(f,d))` | false | false |
| both | `not attacker(fileSecret[])` | false | false |
| both | `event(GcsOpened(f,d)) ==> event(UavSealed(f,d))` | true | true |
| both | `not event(GcsOpened(f,d))` | false | false |

## `sealed_file.pv` with `file_leak_uav.pvl`

... the UAV is captured afterwards (all it holds: its signing key).

| attacker | query (ProVerif's wording) | result | expected |
|---|---|---|---|
| classical | `not attacker_p1(fileSecret[])` | true | true |
| classical | `event(GcsOpened(f,d)) ==> event(UavSealed(f,d))` | true | true |
| classical | `not event(GcsOpened(f,d))` | false | false |
| shor | `not attacker_p1(fileSecret[])` | true | true |
| shor | `event(GcsOpened(f,d)) ==> event(UavSealed(f,d))` | true | true |
| shor | `not event(GcsOpened(f,d))` | false | false |
| mlkem | `not attacker_p1(fileSecret[])` | true | true |
| mlkem | `event(GcsOpened(f,d)) ==> event(UavSealed(f,d))` | true | true |
| mlkem | `not event(GcsOpened(f,d))` | false | false |
| both | `not attacker_p1(fileSecret[])` | false | false |
| both | `event(GcsOpened(f,d)) ==> event(UavSealed(f,d))` | true | true |
| both | `not event(GcsOpened(f,d))` | false | false |

## `sealed_file.pv` with `file_leak_kem.pvl`

... the ground station's ML-KEM recording key alone is stolen.

| attacker | query (ProVerif's wording) | result | expected |
|---|---|---|---|
| classical | `not attacker_p1(fileSecret[])` | true | true |
| classical | `event(GcsOpened(f,d)) ==> event(UavSealed(f,d))` | true | true |
| classical | `not event(GcsOpened(f,d))` | false | false |
| shor | `not attacker_p1(fileSecret[])` | false | false |
| shor | `event(GcsOpened(f,d)) ==> event(UavSealed(f,d))` | true | true |
| shor | `not event(GcsOpened(f,d))` | false | false |
| mlkem | `not attacker_p1(fileSecret[])` | true | true |
| mlkem | `event(GcsOpened(f,d)) ==> event(UavSealed(f,d))` | true | true |
| mlkem | `not event(GcsOpened(f,d))` | false | false |
| both | `not attacker_p1(fileSecret[])` | false | false |
| both | `event(GcsOpened(f,d)) ==> event(UavSealed(f,d))` | true | true |
| both | `not event(GcsOpened(f,d))` | false | false |

## `sealed_file.pv` with `file_leak_x.pvl`

... the ground station's X25519 recording key alone is stolen.

| attacker | query (ProVerif's wording) | result | expected |
|---|---|---|---|
| classical | `not attacker_p1(fileSecret[])` | true | true |
| classical | `event(GcsOpened(f,d)) ==> event(UavSealed(f,d))` | true | true |
| classical | `not event(GcsOpened(f,d))` | false | false |
| shor | `not attacker_p1(fileSecret[])` | true | true |
| shor | `event(GcsOpened(f,d)) ==> event(UavSealed(f,d))` | true | true |
| shor | `not event(GcsOpened(f,d))` | false | false |
| mlkem | `not attacker_p1(fileSecret[])` | false | false |
| mlkem | `event(GcsOpened(f,d)) ==> event(UavSealed(f,d))` | true | true |
| mlkem | `not event(GcsOpened(f,d))` | false | false |
| both | `not attacker_p1(fileSecret[])` | false | false |
| both | `event(GcsOpened(f,d)) ==> event(UavSealed(f,d))` | true | true |
| both | `not event(GcsOpened(f,d))` | false | false |

## `sealed_file.pv` with `file_leak_both.pvl`

... both recording keys are stolen (expected to fail: nothing at rest is forward secret).

| attacker | query (ProVerif's wording) | result | expected |
|---|---|---|---|
| classical | `not attacker_p1(fileSecret[])` | false | false |
| classical | `event(GcsOpened(f,d)) ==> event(UavSealed(f,d))` | true | true |
| classical | `not event(GcsOpened(f,d))` | false | false |
