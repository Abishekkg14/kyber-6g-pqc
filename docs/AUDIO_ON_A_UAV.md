# Can a UAV record sound at all? Cases and exceptions for the audio feature

The audio feature of this system seals whatever encoded audio the UAV is given, stores it and sends it
(`kyber6g/audio/`, `docs/AUDIO_CRYPTANALYSIS_REPORT.txt`). It says nothing about how good that audio is. This note
is about that question: when sound picked up by a UAV is worth sealing, when it is not, and what follows for the
wording of the paper.

Two pages the project owner asked to be read are summarised first; the rest is general background, written from
memory and marked as such. Check every literature reference before citing it.

## 1. What the two pages say

* **Flying Glass, "Do drones have microphones?"** (flyingglass.com.au). Most consumer and professional camera
  drones have no microphone; a microphone can be attached but rarely is, because the drone's own rotors and motors
  drown out what one would want to hear. Extra equipment costs weight, power and flight time. What film crews do
  instead: record the sound on the ground and synchronise it afterwards, or add sound in post-production;
  directional microphones are named as a partial help. The page also notes that recording private conversations
  without consent may breach privacy law (it writes about Australia) and that commercial operation needs its
  licences.
* **A Zhihu answer on whether drones can record sound** (zhihu.com). Ordinary drones do not come with a microphone;
  add-on microphone and loudspeaker units exist; the propeller noise makes what is captured close to useless; early
  gimbal cameras could record sound and the manufacturer removed it for that reason. Sound is added afterwards.

Neither page describes a noise-cancelling method that makes an on-board microphone usable in flight. Both say the
same thing: **in flight, next to the rotors, a plain microphone records the rotors.**

## 2. Why, and what research does about it (background, from memory)

* A multirotor's rotors and motors are loud at the airframe and their sound is harmonic (the blade-passing
  frequency and its multiples, moving with the motor speed) plus broadband air noise; wind adds low-frequency
  noise. A voice on the ground tens of metres away arrives far weaker than that. The signal-to-noise ratios
  reported for microphones on small multirotors are strongly negative (figures between about -10 and -30 dB are
  usual in that literature).
* "Noise cancellation" as in headphones (an anti-phase signal at the ear) is not what helps here. What is used is
  **ego-noise reduction**: several microphones in an array and spatial filtering (beamforming), time-frequency
  masking, the motor speeds as a reference for the harmonic part, and learned speech enhancement; mechanically,
  microphones on a boom or hung below the airframe, away from the rotor wash, with wind screens.
* This is an active research field ("drone audition"), driven by search and rescue: finding a person who calls
  for help from the air. Entry points: the DREGON data set (Strauss, Mordel, Miguet, Deleforge, IROS 2018); Wang
  and Cavallaro, "Acoustic sensing from a multi-rotor drone" (IEEE Sensors Journal, 2018); Hoshiba et al., "Design
  of UAV-embedded microphone array system for sound source localization in outdoor environments" (Sensors, 2017);
  the IEEE Signal Processing Cup 2019. The results there are for localisation and detection more than for
  intelligible speech, and they need a microphone array and processing, not one microphone.

## 3. Cases in which sealed audio from a UAV makes sense

| case | why the rotor problem does not apply, or is dealt with |
|---|---|
| **Landed or perched listening post.** The UAV flies to a place, lands or perches, stops its rotors and listens. | no rotor noise; the UAV is a remote sensor that can also leave again |
| **Microphone array payload with its own processing.** | the payload delivers enhanced audio (section 2); the UAV seals what the payload gives it |
| **Microphone lowered on a tether or held on a boom.** | distance from the rotors; still needs wind protection |
| **Fixed-wing aircraft gliding with the motor off.** | no propulsion noise for the time of the glide |
| **Relay and data mule.** A ground sensor, a team's radio or a recorder hands audio to the UAV, which stores it and carries or forwards it. | the sound was never recorded near the rotors; this is the "store it and send it to the base station" of the project brief |
| **Acoustic event payloads** (short clips around a detected event). | a short clip around a loud event survives noise that speech does not |
| **Voice notes of the crew** attached to a mission's data. | recorded on the ground |

In all of them the properties of the sealed format are what is wanted: only the ground station can open a clip,
the UAV cannot read back what it stored, every clip is signed, and an excerpt can be given to a third party who
checks it against the UAV's public key.

## 4. Exceptions and limits

1. **This prototype has no microphone.** A file in the Pi's inbox stands in for one. Nothing in this repository
   was recorded by the UAV. Do not write "recorded by the UAV's microphone".
2. **In flight with a plain on-board microphone the result is rotor noise.** The feature would seal it faithfully.
   No ego-noise reduction is implemented, and none was tested.
3. **Noise reduction has to happen before sealing or after opening, never in between.** A sealed block cannot be
   processed without its key, on purpose: a cipher that "tolerates noise" or allows processing of the ciphertext
   can also be changed by an attacker (two of the six schemes compared in the cryptanalysis report advertise that
   tolerance). Here the UAV's signature covers the capture as it was made; an enhanced version made on the ground
   after opening is a derived copy that the UAV did not sign, and should be labelled so if it is used as evidence.
4. **Lossy codecs and noise.** The system seals the encoder's frames without decoding them. What a speech codec
   does to a signal that is mostly rotor noise is outside the system.
5. **The uniform shape costs bytes with a variable bit rate** (195 % more in the measured example, about 9 % at a
   constant bit rate). Silence in speech is one of the things the uniform shape hides; whether that is worth the
   bytes depends on the mission.
6. **Bandwidth and latency.** 128 kbit/s of audio is about 4 % of the 3 Mbit/s video stream. Live blocks leave
   the UAV 0.21 s of audio at a time; under loss the missing ones are fetched from the card afterwards.
7. **Law.** Recording people's conversations without consent is restricted in many jurisdictions; the rules for
   emergency services, the military and private operators differ. That is the operator's responsibility and not
   something the software decides.
8. **Electrical noise.** Motor controllers radiate into analogue microphone lines; a real installation needs a
   digital microphone or a shielded, balanced line. Not tested here.

## 5. What the paper may say

* "The UAV node seals encoded audio (from a file that stands in for a microphone in the prototype) ..." - yes.
* "Audio recorded by the UAV in flight" - no.
* "The scheme is independent of the audio source; in flight a usable source needs an array with ego-noise
  reduction, a tethered microphone, or a landed node, none of which is part of this work" - yes.
* The sample used for the statistics plot is a free sound sample supplied by the project owner; name its source
  and licence in the paper if its waveform is printed.
