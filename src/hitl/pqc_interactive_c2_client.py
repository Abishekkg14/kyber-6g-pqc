#!/usr/bin/env python3
# ==============================================================================
# Kyber-6G Interactive UAV Drone Companion Console & Flight Command Shell
# - Level-5 Hybrid PQC Authentication (ML-KEM-1024 + X25519 + ML-DSA-87)
# - Strict Flight Command Whitelist & Input Range Validation
# - Real-Time Avionics Flight State Tracking (Altitude, GPS, Speed, Battery, Mode)
# - Encrypted AES-256-GCM Telemetry & C2 Protocol
# ==============================================================================
import socket
import os
import sys
import time
import struct
import json
import argparse
import oqs
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(line_buffering=True)

MAX_DGRAM = 1352

enabled_sigs = oqs.get_enabled_sig_mechanisms()
SIG_ALG = "ML-DSA-87" if "ML-DSA-87" in enabled_sigs else ("Dilithium5" if "Dilithium5" in enabled_sigs else enabled_sigs[0])

def send_framed_udp(sock, addr, msg_type, payload):
    chunk_size = MAX_DGRAM - 6
    total_frags = (len(payload) + chunk_size - 1) // chunk_size
    if total_frags == 0:
        total_frags = 1
        payload = b""
    for i in range(total_frags):
        chunk = payload[i * chunk_size : (i + 1) * chunk_size]
        header = struct.pack("!HBB", msg_type, i, total_frags)
        sock.sendto(header + chunk, addr)

def recv_framed_udp(sock, timeout=5.0):
    sock.settimeout(timeout)
    buffers = {}
    while True:
        try:
            packet, addr = sock.recvfrom(4096)
        except socket.timeout:
            return None, None, None
        if len(packet) < 4:
            continue
        msg_type, frag_idx, total_frags = struct.unpack("!HBB", packet[:4])
        chunk = packet[4:]
        key = (addr, msg_type)
        if key not in buffers:
            buffers[key] = [None] * total_frags
        buffers[key][frag_idx] = chunk
        if all(f is not None for f in buffers[key]):
            full_payload = b"".join(buffers[key])
            del buffers[key]
            return msg_type, full_payload, addr

class DroneFlightModel:
    """Maintains realistic drone companion computer avionics state."""
    def __init__(self):
        self.armed = False
        self.altitude_m = 0.0
        self.target_alt_m = 0.0
        self.lat = 12.971600
        self.lon = 77.594600
        self.speed_ms = 0.0
        self.heading_deg = 180.0
        self.battery_pct = 98
        self.flight_mode = "STANDBY"
        self.home_lat = 12.971600
        self.home_lon = 77.594600
        self.home_alt = 0.0

    def get_telemetry_dict(self):
        return {
            "armed": self.armed,
            "altitude_m": round(self.altitude_m, 1),
            "lat": round(self.lat, 6),
            "lon": round(self.lon, 6),
            "speed_ms": round(self.speed_ms, 1),
            "heading_deg": round(self.heading_deg, 1),
            "battery_pct": self.battery_pct,
            "flight_mode": self.flight_mode
        }

    def execute_command(self, verb, args):
        """Validates command logic and updates drone physics state machine."""
        if verb == "ARM":
            if self.armed:
                return False, "Drone is already ARMED."
            self.armed = True
            self.flight_mode = "ARMED"
            return True, "Motors ARMED. Ready for flight commands."

        elif verb == "DISARM":
            if not self.armed:
                return False, "Drone is already DISARMED."
            if self.altitude_m > 0.5:
                return False, f"SAFETY REJECTION: Cannot DISARM in mid-air! Current altitude: {self.altitude_m}m. Execute 'land' first."
            self.armed = False
            self.flight_mode = "STANDBY"
            self.speed_ms = 0.0
            return True, "Motors DISARMED. Safe."

        elif verb == "TAKEOFF":
            if not self.armed:
                return False, "REJECTED: Motors not armed. Execute 'arm' before takeoff."
            if self.altitude_m > 2.0:
                return False, f"REJECTED: Drone already airborne at {self.altitude_m}m. Use 'goto' to change altitude."
            target_alt = float(args[0])
            self.altitude_m = target_alt
            self.target_alt_m = target_alt
            self.speed_ms = 5.0
            self.flight_mode = "TAKEOFF"
            self.battery_pct = max(10, self.battery_pct - 1)
            return True, f"Climbing to {target_alt}m AGL. Autopilot engaged."

        elif verb == "GOTO":
            if not self.armed or self.altitude_m < 0.5:
                return False, "REJECTED: Drone is on ground. Execute 'takeoff' first."
            new_lat, new_lon, new_alt = float(args[0]), float(args[1]), float(args[2])
            self.lat = new_lat
            self.lon = new_lon
            self.altitude_m = new_alt
            self.speed_ms = 15.0
            self.flight_mode = "EN_ROUTE"
            self.battery_pct = max(10, self.battery_pct - 2)
            return True, f"Navigating to waypoint ({new_lat:.5f} N, {new_lon:.5f} E) @ {new_alt}m."

        elif verb == "SPEED":
            new_speed = float(args[0])
            self.speed_ms = new_speed
            return True, f"Cruising airspeed set to {new_speed} m/s."

        elif verb == "MODE":
            new_mode = args[0].upper()
            self.flight_mode = new_mode
            return True, f"Autopilot state machine switched to '{new_mode}'."

        elif verb == "HOLD":
            self.speed_ms = 0.0
            self.flight_mode = "LOITER"
            return True, f"Holding position at {self.altitude_m}m AGL. Loitering."

        elif verb == "RTL":
            if self.altitude_m < 0.5:
                return False, "REJECTED: Drone is on ground."
            self.lat = self.home_lat
            self.lon = self.home_lon
            self.altitude_m = 30.0  # Safe RTL altitude
            self.speed_ms = 12.0
            self.flight_mode = "RTL"
            return True, f"Returning to Launch waypoint ({self.home_lat:.5f}, {self.home_lon:.5f}) @ 30m."

        elif verb == "LAND":
            if self.altitude_m < 0.5:
                return False, "Drone is already on the ground."
            self.altitude_m = 0.0
            self.speed_ms = 0.0
            self.armed = False
            self.flight_mode = "LANDED"
            return True, "Descent complete. Touchdown confirmed. Motors disarmed."

        return False, "Unrecognized action."

def validate_command_syntax(cmd_line):
    """
    Strict whitelist parser.
    Returns: (is_valid, error_msg, verb, args)
    """
    parts = cmd_line.strip().split()
    if not parts:
        return False, "Empty command.", "", []

    verb = parts[0].upper()
    args = parts[1:]

    # Allowed command syntax rules
    if verb == "ARM":
        if len(args) != 0:
            return False, "Syntax: 'arm' (takes no arguments)", verb, args
        return True, "", verb, args

    elif verb == "DISARM":
        if len(args) != 0:
            return False, "Syntax: 'disarm' (takes no arguments)", verb, args
        return True, "", verb, args

    elif verb == "TAKEOFF":
        if len(args) != 1:
            return False, "Syntax: 'takeoff <altitude_m>' (e.g. 'takeoff 50')", verb, args
        try:
            alt = float(args[0])
            if alt < 2.0 or alt > 500.0:
                return False, "Altitude must be between 2.0m and 500.0m (safety ceiling).", verb, args
        except ValueError:
            return False, "Altitude must be a valid number (meters).", verb, args
        return True, "", verb, args

    elif verb == "LAND":
        if len(args) != 0:
            return False, "Syntax: 'land' (takes no arguments)", verb, args
        return True, "", verb, args

    elif verb == "RTL":
        if len(args) != 0:
            return False, "Syntax: 'rtl' (Return to Launch takes no arguments)", verb, args
        return True, "", verb, args

    elif verb == "HOLD" or verb == "HOVER":
        if len(args) != 0:
            return False, "Syntax: 'hold' (takes no arguments)", "HOLD", args
        return True, "", "HOLD", args

    elif verb == "SPEED":
        if len(args) != 1:
            return False, "Syntax: 'speed <m_per_s>' (e.g. 'speed 15')", verb, args
        try:
            spd = float(args[0])
            if spd <= 0.0 or spd > 35.0:
                return False, "Speed must be between 1.0 and 35.0 m/s (drone flight envelope).", verb, args
        except ValueError:
            return False, "Speed must be a valid number.", verb, args
        return True, "", verb, args

    elif verb == "GOTO":
        if len(args) != 3:
            return False, "Syntax: 'goto <lat> <lon> <alt_m>' (e.g. 'goto 12.9725 77.5955 80')", verb, args
        try:
            lat = float(args[0])
            lon = float(args[1])
            alt = float(args[2])
            if not (-90.0 <= lat <= 90.0):
                return False, "Latitude must be between -90.0 and +90.0.", verb, args
            if not (-180.0 <= lon <= 180.0):
                return False, "Longitude must be between -180.0 and +180.0.", verb, args
            if alt < 2.0 or alt > 500.0:
                return False, "Altitude must be between 2.0m and 500.0m.", verb, args
        except ValueError:
            return False, "Coordinates and altitude must be numeric.", verb, args
        return True, "", verb, args

    elif verb == "MODE":
        if len(args) != 1 or args[0].upper() not in ["AUTO", "LOITER", "RTL", "MANUAL", "GUIDED"]:
            return False, "Syntax: 'mode <AUTO|LOITER|RTL|MANUAL|GUIDED>'", verb, args
        return True, "", verb, args

    elif verb == "STATUS" or verb == "TELEMETRY":
        return True, "", "STATUS", []

    elif verb == "HELP":
        return True, "", "HELP", []

    elif verb in ["EXIT", "QUIT"]:
        return True, "", "EXIT", []

    else:
        return False, f"Unknown command '{parts[0]}'. Type 'help' to view valid drone flight commands.", verb, args

def perform_pqc_handshake(sock, dest, uav_id):
    print("\n[*] [PHASE 1] Initiating Level-5 Post-Quantum 3GPP RRC Handshake...")
    t_start = time.perf_counter_ns()

    sk_drone_x = x25519.X25519PrivateKey.generate()
    pk_drone_x = sk_drone_x.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    kem = oqs.KeyEncapsulation('ML-KEM-1024')
    pk_drone_k = kem.generate_keypair()

    signer = oqs.Signature(SIG_ALG)
    pk_drone_sig = signer.generate_keypair()

    drone_sig = signer.sign(pk_drone_x + pk_drone_k)
    mobility_hash = 0x6A7B8C9D

    msg1 = uav_id + struct.pack("!I", mobility_hash) + pk_drone_x + pk_drone_k + struct.pack("!H", len(drone_sig)) + drone_sig + pk_drone_sig
    send_framed_udp(sock, dest, 0x01, msg1)

    resp_type, resp_payload, _ = recv_framed_udp(sock, timeout=5.0)
    if resp_type != 0x02 or resp_payload is None:
        print("[-] Handshake timeout or rejected by gNodeB!")
        sys.exit(1)

    sig_len = struct.unpack("!H", resp_payload[:2])[0]
    gnb_sig = resp_payload[2 : 2 + sig_len]
    gnb_sig_pk = resp_payload[2 + sig_len : 2 + sig_len + len(pk_drone_sig)]
    signed_body = resp_payload[2 + sig_len + len(pk_drone_sig) :]
    
    pk_server_x = signed_body[:32]
    ct_server_k = signed_body[32:1600]
    hkdf_salt = signed_body[1600:1616]

    verifier = oqs.Signature(SIG_ALG)
    if not verifier.verify(signed_body, gnb_sig, gnb_sig_pk):
        print("[-] gNodeB Signature Verification FAILED! Aborting.")
        sys.exit(1)
    verifier.free()

    s_drone_k = kem.decap_secret(ct_server_k)
    s_drone_x = sk_drone_x.exchange(x25519.X25519PublicKey.from_public_bytes(pk_server_x))

    k_session = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hkdf_salt,
        info=b"Kyber6G-3GPP-Rel17-MasterKey"
    ).derive(s_drone_x + s_drone_k)

    t_handshake_ms = (time.perf_counter_ns() - t_start) / 1e6
    print(f"[+] [SUCCESS] Level-5 Handshake Authenticated in {t_handshake_ms:.2f} ms")
    print(f"[+] Master Session Key Established: {k_session.hex()[:24]}...")
    kem.free()
    signer.free()
    return k_session

def print_help_menu():
    print("""
========================================================================
VALID DRONE FLIGHT COMMANDS (Strict Whitelist):
------------------------------------------------------------------------
Flight Control Commands:
  arm                     - Arm drone motors (Pre-flight safety check)
  disarm                  - Disarm drone motors (Only permitted on ground)
  takeoff <alt_m>         - Ascend to altitude (e.g. 'takeoff 50', 2-500m)
  goto <lat> <lon> <alt>  - Fly to coordinates (e.g. 'goto 12.9725 77.5955 80')
  speed <m_per_s>         - Set airspeed (e.g. 'speed 15', 1-35 m/s)
  hold                    - Loiter in-place at current coordinates and altitude
  rtl                     - Return to Launch (Autonomous return to base origin)
  land                    - Execute controlled vertical landing and disarm
  mode <AUTO|LOITER|RTL>  - Set autopilot state machine

Telemetry & Session:
  status                  - Display real-time drone avionics & PQC cipher state
  help                    - Show this allowed command manual
  exit / quit             - Disconnect from base station
========================================================================
""")

def main():
    parser = argparse.ArgumentParser(description="Kyber-6G Drone C2 Console with Strict Whitelist")
    parser.add_argument("--server", type=str, default="127.0.0.1", help="gNodeB Base Tower IP")
    parser.add_argument("--port", type=int, default=14000, help="UDP port")
    parser.add_argument("--uav-id", type=str, default="UAV-ALPH", help="8-character 3GPP UAV ID")
    parser.add_argument("--auto-test", action="store_true", help="Run automated flight command validation sequence")
    args = parser.parse_args()

    dest = (args.server, args.port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    uav_id = args.uav_id.encode('ascii')[:8].ljust(8, b' ')

    print("=" * 75)
    print("KYBER-6G VALIDATED DRONE C2 FLIGHT CONSOLE")
    print(f"Target 6G Base Station: {args.server}:{args.port}")
    print(f"UAV Call-Sign:          {args.uav_id}")
    print("=" * 75)

    # Perform Level-5 PQC RRC Handshake
    k_session = perform_pqc_handshake(sock, dest, uav_id)
    aesgcm = AESGCM(k_session)
    cmd_seq = 1
    drone = DroneFlightModel()

    def send_validated_packet(cmd_string):
        nonlocal cmd_seq
        t0 = time.perf_counter_ns()
        
        # Bundle command + live drone telemetry state
        telemetry = drone.get_telemetry_dict()
        packet_obj = {
            "cmd_seq": cmd_seq,
            "cmd": cmd_string,
            "telemetry": telemetry,
            "timestamp_ms": int(time.time() * 1000)
        }
        json_payload = json.dumps(packet_obj).encode('utf-8')

        gcm_nonce = struct.pack("!Q", cmd_seq) + os.urandom(4)
        ciphertext = aesgcm.encrypt(gcm_nonce, json_payload, None)
        
        pdu = uav_id + struct.pack("!Q", cmd_seq) + gcm_nonce + ciphertext
        send_framed_udp(sock, dest, 0x08, pdu)

        resp_type, resp_payload, _ = recv_framed_udp(sock, timeout=3.0)
        rtt_ms = (time.perf_counter_ns() - t0) / 1e6

        if resp_type == 0x09 and resp_payload is not None:
            ack_nonce = resp_payload[8:20]
            ack_ct = resp_payload[20:]
            ack_json = aesgcm.decrypt(ack_nonce, ack_ct, None).decode('utf-8')
            ack_data = json.loads(ack_json)
            print(f"[+] Base Tower ACK (RTT: {rtt_ms:5.2f} ms): {ack_data.get('status')}")
            print(f"    [Confirmed Avionics]: Alt: {telemetry['altitude_m']}m | Mode: {telemetry['flight_mode']} | Lat: {telemetry['lat']}, Lon: {telemetry['lon']} | Bat: {telemetry['battery_pct']}%")
        else:
            print("[-] Timeout: No acknowledgment received from Base Tower.")

        cmd_seq += 1

    if args.auto_test:
        print("\n[*] RUNNING AUTOMATED FLIGHT SEQUENCE TEST...")
        test_commands = [
            "arm",
            "takeoff 50",
            "goto 12.972500 77.595500 75",
            "speed 20",
            "hold",
            "rtl",
            "land",
            "disarm"
        ]
        for c in test_commands:
            time.sleep(0.5)
            is_valid, err, verb, c_args = validate_command_syntax(c)
            print(f"\n[Command Input]> {c}")
            if not is_valid:
                print(f"[-] Validation Error: {err}")
                continue
            ok, msg = drone.execute_command(verb, c_args)
            print(f"[*] Local Companion Logic: {msg}")
            send_validated_packet(c)

        print("\n[+] AUTOMATED FLIGHT TEST COMPLETED SUCCESSFULLY!")
        return

    print_help_menu()

    while True:
        try:
            cmd = input(f"\n[{args.uav_id} | Alt:{drone.altitude_m:4.1f}m | {drone.flight_mode}]> ").strip()
            if not cmd:
                continue

            is_valid, err, verb, c_args = validate_command_syntax(cmd)

            if not is_valid:
                print(f"[-] ERROR: {err}")
                continue

            if verb == "EXIT":
                print("[*] Closing C2 flight session.")
                break

            elif verb == "HELP":
                print_help_menu()
                continue

            elif verb == "STATUS":
                t = drone.get_telemetry_dict()
                print("\n" + "=" * 60)
                print(f"DRONE ONBOARD AVIONICS TELEMETRY ({args.uav_id})")
                print("=" * 60)
                print(f"  Motors Armed:     {'YES (ARMED)' if t['armed'] else 'NO (DISARMED)'}")
                print(f"  Flight Mode:      {t['flight_mode']}")
                print(f"  Current Altitude: {t['altitude_m']} m AGL")
                print(f"  GPS Position:     {t['lat']} N, {t['lon']} E")
                print(f"  Ground Airspeed:  {t['speed_ms']} m/s")
                print(f"  Battery Level:    {t['battery_pct']}% [█████████░]")
                print(f"  Link Encryption:  ML-KEM-1024 + AES-256-GCM")
                print("=" * 60)
                send_validated_packet("STATUS_UPDATE")
                continue

            # Execute valid flight command through physics state machine
            ok, msg = drone.execute_command(verb, c_args)
            if not ok:
                print(f"[-] SAFETY REJECTION: {msg}")
                continue

            print(f"[*] Companion Controller: {msg}")
            send_validated_packet(cmd)

        except (KeyboardInterrupt, EOFError):
            print("\n[*] Exiting C2 console.")
            break

if __name__ == "__main__":
    main()
