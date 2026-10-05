/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
// SPDX-License-Identifier: GPL-2.0-only
//
// k6g-swarm-sim: packet-level simulation of the session operations of the Kyber-6G secure link.
//
// What is simulated. The three operations of the implemented protocol (kyber6g/transport/link.py) - the full
// 1.5-RTT handshake, the 1-RTT Cached RapidRekey and the PQ ratchet - as the datagrams they really are: the same
// message sizes, the same fragmentation, the same repeat timers and attempt limits, reassembly that combines the
// fragments of repeated transmissions, the answer cache of the ground station. The time each side spends
// computing is drawn from what was MEASURED in the running system (simulation/calibrate.py writes the file this
// program reads; nothing in the protocol model is typed in here). Beside the operations every UAV sends its video
// stream (frame sizes as measured), which loads the link and the ground station's single receive thread.
//
// Two links:
//   --link=testbed   a replica of the test bed (one UAV, Wi-Fi): a message of k datagrams takes what a message of
//                    k datagrams was measured to take, datagrams are lost independently at --loss. Used to check
//                    the model against the measurements that were NOT used to calibrate it.
//   --link=nr        a 5G NR cell (5G-LENA): gNB, N UAVs as UEs with 3GPP channel, scheduler, HARQ and RLC, the
//                    ground station behind the core network. This is the extrapolation: what the test bed, with
//                    one UAV on Wi-Fi, cannot show.
//
// Output: one line per operation (O,...), one per UAV for its video (V,...), one for the run (M,...).

#include "ns3/antenna-module.h"
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/nr-module.h"
#include "ns3/point-to-point-module.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("K6gSwarmSim");

namespace
{

// ------------------------------------------------------------------------------------------------- calibration
struct Calib
{
    std::map<std::string, double> scalar;
    std::map<std::string, std::vector<double>> samples; // as measured (order kept)
    std::map<std::string, std::vector<double>> sorted;  // for quantiles
    std::map<std::string, std::map<std::string, double>> profile;

    void Load(const std::string& path)
    {
        std::ifstream f(path);
        NS_ABORT_MSG_IF(!f, "cannot read the calibration file " << path << " (run simulation/calibrate.py)");
        std::string line;
        while (std::getline(f, line))
        {
            if (line.empty() || line[0] == '#')
            {
                continue;
            }
            std::istringstream is(line);
            std::string kind;
            std::string name;
            is >> kind >> name;
            if (kind == "scalar")
            {
                is >> scalar[name];
            }
            else if (kind == "samples")
            {
                size_t n = 0;
                is >> n;
                std::vector<double> v(n);
                for (auto& x : v)
                {
                    is >> x;
                }
                samples[name] = v;
                std::sort(v.begin(), v.end());
                sorted[name] = v;
            }
            else if (kind == "profile")
            {
                std::string key;
                double val;
                while (is >> key >> val)
                {
                    profile[name][key] = val;
                }
            }
        }
    }

    double S(const std::string& name) const
    {
        auto it = scalar.find(name);
        NS_ABORT_MSG_IF(it == scalar.end(), "calibration: no scalar " << name);
        return it->second;
    }

    bool Has(const std::string& name) const
    {
        auto it = samples.find(name);
        return it != samples.end() && !it->second.empty();
    }

    double Quantile(const std::string& name, double u) const
    {
        auto it = sorted.find(name);
        NS_ABORT_MSG_IF(it == sorted.end() || it->second.empty(), "calibration: no samples " << name);
        const auto& v = it->second;
        double pos = u * (v.size() - 1);
        size_t i = static_cast<size_t>(pos);
        if (i + 1 >= v.size())
        {
            return v.back();
        }
        return v[i] + (v[i + 1] - v[i]) * (pos - i);
    }
};

// ---------------------------------------------------------------------------------------------------- datagram
enum DgType : uint8_t
{
    CH = 1, // ClientHello fragment
    SH,     // ServerHello fragment
    CF,     // ClientFinished
    RKREQ,  // cached-rekey request
    RKRESP, // cached-rekey answer
    CTRL,   // one part of a control message inside the session (kind says which)
    VIDEO   // one chunk of a video frame
};

enum CtrlKind : uint8_t
{
    RT_REQ = 1, // PQ ratchet request
    RT_RESP,    // PQ ratchet answer
    KF_REQ      // keyframe request (design study, not in the implementation)
};

enum OpKind : int
{
    FULL = 0,
    CACHED = 1,
    RATCHET = 2
};

const char* const OP_NAME[] = {"full", "cached", "ratchet"};

#pragma pack(push, 1)
struct Dg
{
    uint8_t type{0};
    uint8_t kind{0};    // CTRL: which message; VIDEO: bit0 = keyframe
    uint16_t uav{0};
    uint32_t msg{0};    // handshake messages: the same for every repetition (content-derived id); control: new each time
    uint8_t idx{0};
    uint8_t cnt{1};
    uint8_t need{1};    // VIDEO: chunks needed to rebuild the frame (cnt - parity chunks)
    uint8_t attempt{0};
    uint32_t op{0};     // the operation it belongs to (UAV's counter)
    uint32_t frame{0};
    float aux{0};       // answers: time the ground station computed (ms)
    double u{0};        // quantile that couples the two directions of one exchange (test-bed link)
};
#pragma pack(pop)

struct Params
{
    std::string link{"testbed"};
    std::string profile{"hybrid5"};
    std::string calib{"simulation/calibration/k6g_calibration.txt"};
    std::string out{"k6g_run.csv"};
    std::string tag{""};
    uint32_t nUav{1};
    double simTime{20.0};
    double loss{0.0};          // datagram loss probability, each direction (test-bed link)
    uint32_t opsPerUav{5};     // operations of EACH kind per UAV
    double opGap{0.5};         // seconds between two operations of one UAV
    std::string ops{"full,cached,ratchet"};
    bool storm{false};         // every UAV starts its first handshake at the same instant (ground station restarted)
    bool video{true};
    double videoScale{1.0};    // frame size relative to the measured stream
    uint32_t fecParity{0};     // design study: parity chunks per video frame (any `need` of `cnt` chunks rebuild it)
    bool kfRequest{false};     // design study: the ground station asks for a keyframe when a frame is lost
    double retxScale{1.0};     // design study: all repeat intervals times this
    bool adaptiveRetx{false};  // design study: repeat after 3 x the last round trip that needed no repeat (min 30 ms), never later than the fixed timer
    bool combine{true};        // fragments of repeated handshake messages combine (as implemented); 0: every repeat on its own
    uint32_t gcsWorkers{1};    // design study: threads handling requests at the ground station
    bool gcsRxCost{true};      // every datagram costs the ground station's receive thread its measured time
    double fragPayload{0};     // design study: fragment payload in bytes (0 = as implemented)
    // NR
    double freq{3.5e9};
    double bw{100e6};
    uint32_t numerology{1};
    std::string tdd{"DL|DL|DL|S|UL|DL|DL|S|UL|UL|"};
    double gnbTx{38.0};
    double ueTx{23.0};
    double radius{400.0};
    double rMin{30.0};
    double hMin{60.0};
    double hMax{120.0};
    double speed{0.0};
    double backhaulMs{1.0};
    double chUpdateMs{0.0};
    bool cellHandshake{true};  // a moving UAV makes a full handshake when it enters another position cell (as implemented)
    std::string scheduler{"tdma"}; // tdma (one beam, one UAV at a time) or ofdma
    bool ulPowerControl{false};    // uplink power control of TS 38.213 (off: full power over the allocation, the library's default)
    int32_t p0Pusch{-90};          // target received power per resource block (dBm) of that power control
    bool debugPhy{false};      // write one line per transport block that was not decoded (T,...)
};

Params P;
Calib C;
std::map<std::string, double> PR; // the chosen cryptographic configuration
std::ofstream OUT;
Ptr<UniformRandomVariable> RNG;

double
U()
{
    return RNG->GetValue(0.0, 1.0);
}

double
Draw(const std::string& name)
{
    auto it = C.samples.find(name);
    NS_ABORT_MSG_IF(it == C.samples.end() || it->second.empty(), "calibration: no samples " << name);
    return it->second[RNG->GetInteger(0, it->second.size() - 1)];
}

double
Now()
{
    return Simulator::Now().GetSeconds();
}

double
FragPayload()
{
    return P.fragPayload > 0 ? P.fragPayload : C.S("frag_payload");
}

class Gcs;
class Uav;

// -------------------------------------------------------------------------------------------------------- link
struct Net
{
    std::vector<Uav*> uavs;
    Gcs* gcs{nullptr};
    std::vector<Ptr<Socket>> uavSock;
    Ptr<Socket> gcsSock;
    std::vector<Address> uavAddr;
    std::vector<bool> uavKnown;
    Address gcsAddr;
    uint64_t upSent{0}, upLost{0}, downSent{0}, downLost{0}, upBytes{0}, downBytes{0}, upRecv{0}, downRecv{0};
    // NR: transport blocks received, not decoded at some transmission, and given up after the last HARQ transmission
    uint64_t ulTb{0}, ulTbErr{0}, ulTbLost{0}, dlTb{0}, dlTbErr{0}, dlTbLost{0};
    double ulSinrDbSum{0}, ulMcsSum{0};

    // Test bed: one-way latency of datagram `idx` of a message of `cnt` datagrams. A message of k datagrams each way
    // was MEASURED to take rtt_k (round trip); one direction is half of it, and both directions of one exchange use
    // the same quantile u, so a request and its answer together reproduce the measured distribution.
    static double TestbedDelay(const Dg& d)
    {
        if (d.type == VIDEO)
        {
            return C.Quantile("rtt_k1_ms", d.u) / 2000.0 + d.idx * C.S("uav_tx_us") * 1e-6;
        }
        int k = std::min<int>(d.cnt, 6);
        while (k > 1 && !C.Has("rtt_k" + std::to_string(k) + "_ms"))
        {
            --k;
        }
        double l1 = C.Quantile("rtt_k1_ms", d.u) / 2000.0;
        if (d.cnt <= 1 || k <= 1)
        {
            return l1;
        }
        double lk = C.Quantile("rtt_k" + std::to_string(k) + "_ms", d.u) / 2000.0;
        if (d.cnt > 6 && C.Has("rtt_k5_ms") && C.Has("rtt_k6_ms"))
        { // longer messages than were measured: the last measured step repeated
            double step = std::max(0.0, C.Quantile("rtt_k6_ms", d.u) - C.Quantile("rtt_k5_ms", d.u)) / 2000.0;
            lk += step * (d.cnt - 6);
        }
        return l1 + std::max(0.0, lk - l1) * d.idx / (d.cnt - 1.0);
    }

    void Up(Dg d, uint32_t size);
    void Down(Dg d, uint32_t size);
    void RxGcs(Ptr<Socket> s);
    void RxUav(Ptr<Socket> s);
};

Net NET;

// -------------------------------------------------------------------------------------------------------- UAV
class Uav
{
  public:
    uint16_t id{0};
    bool busy{false};
    bool initial{true};
    int kind{FULL};
    uint32_t opSeq{0};
    uint32_t ctrlSeq{0};
    double t0{0}, tBuilt{0}, tFirstSend{0}, buildMs{0}, procMs{0}, gcsMs{0}, lastRtt{0.0}, phase{0};
    int tx{0};
    bool answered{false};
    std::set<uint8_t> got;
    std::map<uint32_t, std::set<uint8_t>> ctrlGot;
    EventId timer;
    std::vector<int> plan;
    size_t planIdx{0};
    // video
    uint32_t frame{0};
    uint64_t framesSent{0}, chunksSent{0}, keyRequests{0};
    bool forceKey{false};
    uint64_t opsOk{0}, opsFail{0}, opsSkipped{0};
    bool up{false};      // a session exists (the first handshake has completed)
    bool planned{false}; // the operation in progress is one of the planned ones
    double backoff{0.0};
    // position cell (kyber6g/crypto/handshake.py, MobilityTracker): a session belongs to the cell it was made in
    Ptr<MobilityModel> mm;
    bool cellKnown{false}, mobOp{false};
    long cellI{0}, cellJ{0}, sessI{0}, sessJ{0}, opI{0}, opJ{0};
    double mobBackoff{0.0}, mobRetryAt{0.0};
    uint64_t cellChanges{0};

    // The link manager looks at the position every tick. The cell changes only when the position is more than
    // `cell_margin` of a cell beyond the old cell's edge; then the session is renewed by a full handshake, made in
    // place (the running session carries the traffic meanwhile) and tried again further apart when it fails.
    void CellTick()
    {
        Vector p = mm->GetPosition();
        double fi = p.x / C.S("cell_m");
        double fj = p.y / C.S("cell_m");
        double lim = 0.5 + C.S("cell_margin");
        if (!cellKnown)
        {
            cellI = std::lround(fi);
            cellJ = std::lround(fj);
            cellKnown = true;
        }
        else if (std::fabs(fi - cellI) > lim || std::fabs(fj - cellJ) > lim)
        {
            cellI = std::lround(fi);
            cellJ = std::lround(fj);
            ++cellChanges;
        }
        if (up && !busy && (cellI != sessI || cellJ != sessJ) && Now() >= mobRetryAt)
        {
            mobOp = true;
            StartOp(FULL);
        }
        Simulator::Schedule(Seconds(C.S("manager_tick_s")), &Uav::CellTick, this);
    }

    double Scale(const std::string& k) const
    {
        auto it = PR.find(k);
        return it == PR.end() ? 1.0 : it->second;
    }

    // The planned operations run one after the other, each `opGap` after the one before has ended (as the
    // measurement on the test bed ran them), so a slow operation never pushes another one out.
    void NextPlanned()
    {
        if (planIdx >= plan.size())
        {
            return;
        }
        if (busy || !up)
        { // the session is not there yet (first handshake still running, or being tried again)
            Simulator::Schedule(Seconds(0.1), &Uav::NextPlanned, this);
            return;
        }
        planned = true;
        StartOp(plan[planIdx++]);
    }

    void StartOp(int k)
    {
        if (busy)
        { // the implementation serialises handshake and rekey with one lock
            ++opsSkipped;
            return;
        }
        busy = true;
        kind = k;
        ++opSeq;
        t0 = Now();
        opI = cellI; // the cell this operation is made in (a handshake carries it; the new session belongs to it)
        opJ = cellJ;
        tx = 0;
        answered = false;
        got.clear();
        ctrlGot.clear();
        phase = U() * C.S("manager_tick_s");
        if (k == FULL)
        {
            buildMs = Draw("uav_full_build_ms") * Scale("scale_full_build");
        }
        else if (k == CACHED)
        {
            buildMs = Draw("uav_cached_build_ms");
        }
        else
        {
            buildMs = Draw("uav_ratchet_build_ms") * Scale("scale_ratchet_build");
        }
        Simulator::Schedule(Seconds(buildMs / 1000.0), &Uav::Send, this);
    }

    double RetxInterval(double fixed) const
    {
        fixed *= P.retxScale;
        if (P.adaptiveRetx && lastRtt > 0)
        { // three round trips, never later than the fixed timer would have fired
            return std::min(fixed, std::max(0.030, 3.0 * lastRtt));
        }
        return fixed;
    }

    void Send()
    {
        if (!busy || answered)
        {
            return;
        }
        ++tx;
        if (tx == 1)
        {
            tBuilt = tFirstSend = Now();
        }
        Dg d;
        d.uav = id;
        d.op = opSeq;
        d.attempt = tx;
        d.u = U();
        double spacing = P.link == "nr" ? C.S("uav_tx_us") * 1e-6 : 0.0;
        if (kind == FULL)
        {
            uint32_t body = PR.at("ch_bytes");
            uint32_t fp = FragPayload();
            uint32_t cnt = (body + fp - 1) / fp;
            d.type = CH;
            d.msg = opSeq; // content-derived in the implementation: every repetition carries the same id
            d.cnt = cnt;
            for (uint32_t i = 0; i < cnt; ++i)
            {
                // repetitions alternate the order of the fragments (a periodic loss must not hit the same one twice)
                uint32_t j = (tx % 2 == 0) ? cnt - 1 - i : i;
                d.idx = j;
                uint32_t sz = (j + 1 < cnt ? fp : body - fp * (cnt - 1)) + C.S("hs_hdr");
                Simulator::Schedule(Seconds(i * spacing), &Net::Up, &NET, d, sz);
            }
            timer = Simulator::Schedule(Seconds(RetxInterval(C.S("hs_retx_s"))), &Uav::OnTimer, this);
        }
        else if (kind == CACHED)
        {
            d.type = RKREQ;
            d.msg = opSeq;
            NET.Up(d, C.S("rekey_req_bytes") + C.S("hs_hdr"));
            timer = Simulator::Schedule(Seconds(RetxInterval(C.S("rekey_retx_s"))), &Uav::OnTimer, this);
        }
        else
        {
            uint32_t body = PR.at("ratchet_req_bytes");
            uint32_t ck = C.S("ctrl_chunk");
            uint32_t cnt = (body + ck - 1) / ck;
            d.type = CTRL;
            d.kind = RT_REQ;
            d.msg = ++ctrlSeq; // a control message sent again is a new message: its parts do not combine with the old ones
            d.cnt = cnt;
            for (uint32_t i = 0; i < cnt; ++i)
            {
                d.idx = i;
                uint32_t sz = (i + 1 < cnt ? ck : body - ck * (cnt - 1)) + C.S("rec_hdr") + C.S("rec_tag") + (cnt > 1 ? C.S("ctrl_part_ext") : 0);
                Simulator::Schedule(Seconds(i * spacing), &Net::Up, &NET, d, sz);
            }
            // the link manager repeats the request when it is older than 0.35 s x (times sent), looking every 0.1 s
            double next = tx < C.S("ratchet_max_tx") ? RetxInterval(C.S("ratchet_retx_s")) * tx + phase : C.S("ratchet_timeout_s") * P.retxScale;
            timer = Simulator::Schedule(Seconds(std::max(1e-6, tFirstSend + next - Now())), &Uav::OnTimer, this);
        }
    }

    void OnTimer()
    {
        if (!busy || answered)
        {
            return;
        }
        int maxTx = kind == FULL ? C.S("hs_max_tx") : (kind == CACHED ? C.S("rekey_max_tx") : C.S("ratchet_max_tx"));
        if (tx < maxTx)
        {
            Send();
        }
        else
        {
            Finish(false, kind == RATCHET ? "no answer" : "timeout");
        }
    }

    void OnDgram(Dg d)
    {
        if (d.type == CTRL && d.kind == KF_REQ)
        {
            forceKey = true;
            ++keyRequests;
            return;
        }
        if (!busy || answered || d.op != opSeq)
        {
            return;
        }
        bool complete = false;
        if (d.type == SH && kind == FULL)
        {
            if (P.combine)
            {
                got.insert(d.idx); // fragments of repeated answers combine (same message id)
                complete = got.size() >= static_cast<size_t>(d.cnt);
            }
            else
            { // ablation: an answer counts only if all fragments of ONE transmission of it arrive
                auto& s = ctrlGot[0x80000000u | d.attempt];
                s.insert(d.idx);
                complete = s.size() >= static_cast<size_t>(d.cnt);
            }
        }
        else if (d.type == RKRESP && kind == CACHED)
        {
            complete = true;
        }
        else if (d.type == CTRL && d.kind == RT_RESP && kind == RATCHET)
        {
            auto& s = ctrlGot[d.msg];
            s.insert(d.idx);
            complete = s.size() >= static_cast<size_t>(d.cnt);
        }
        if (!complete)
        {
            return;
        }
        answered = true;
        timer.Cancel();
        gcsMs = d.aux;
        if (tx == 1)
        { // a round trip is only known when nothing was repeated: after a repeat it is not known which transmission
          // was answered (Karn's rule). Taking every exchange made the timer grow without bound under loss.
            lastRtt = Now() - tFirstSend;
        }
        if (kind == FULL)
        {
            procMs = Draw("uav_full_process_ms") * Scale("scale_full_process");
        }
        else if (kind == CACHED)
        {
            procMs = Draw("uav_cached_process_ms");
        }
        else
        {
            procMs = Draw("uav_ratchet_finish_ms") * Scale("scale_ratchet_finish");
        }
        double host = P.link == "nr" ? C.S("host_msg_ms") : 0.0;
        Simulator::Schedule(Seconds((host + procMs) / 1000.0), &Uav::Processed, this);
    }

    void Processed()
    {
        double waitMs = (Now() - tBuilt) * 1000.0; // as the implementation reports it: network + ground station + own processing
        // what follows the processing of the answer: installing the new session (and, for the two handshakes, sending
        // the Finished message); each as it was timed on the UAV
        double finMs = Draw(kind == CACHED ? "uav_cached_finish_ms" : (kind == FULL ? "uav_full_finish_ms" : "uav_ratchet_install_ms"));
        Simulator::Schedule(Seconds(finMs / 1000.0), &Uav::Done, this, waitMs, finMs);
    }

    void Done(double waitMs, double finMs)
    {
        if (kind != RATCHET)
        {
            Dg d;
            d.type = CF;
            d.uav = id;
            d.op = opSeq;
            d.u = U();
            NET.Up(d, C.S("cf_bytes") + C.S("hs_hdr"));
        }
        Finish(true, "", waitMs, finMs);
    }

    void Finish(bool ok, const std::string& why, double waitMs = 0, double finMs = 0)
    {
        timer.Cancel();
        // the ratchet's own time, as the implementation reports it, starts when the request is sent (its keys are made before)
        double total = (Now() - (kind == RATCHET ? tBuilt : t0)) * 1000.0;
        (ok ? opsOk : opsFail)++;
        // column `initial`: 1 = the first handshake of the UAV, 2 = a handshake after a change of position cell, 0 = planned
        OUT << "O," << id << "," << opSeq << "," << OP_NAME[kind] << "," << (initial ? 1 : (mobOp ? 2 : 0)) << "," << std::fixed
            << std::setprecision(6) << t0 << "," << (ok ? 1 : 0) << "," << std::setprecision(4) << total << "," << buildMs << "," << waitMs << ","
            << procMs << "," << finMs << "," << gcsMs << "," << tx << "," << why << "\n";
        busy = false;
        if (ok && kind == FULL)
        {
            sessI = opI;
            sessJ = opJ;
        }
        if (initial)
        {
            if (ok)
            {
                initial = false;
                up = true;
            }
            else
            { // no session yet: the link manager tries again, further apart each time (0.5 s doubling up to 8 s)
                Simulator::Schedule(Seconds(backoff), &Uav::StartOp, this, static_cast<int>(FULL));
                backoff = std::min(backoff * 2, C.S("manager_backoff_max_s"));
            }
            return;
        }
        if (mobOp)
        {
            mobOp = false;
            if (ok)
            {
                mobBackoff = C.S("manager_backoff_s");
            }
            else
            { // the running session goes on working; the handshake is tried again, further apart each time
                mobRetryAt = Now() + mobBackoff;
                mobBackoff = std::min(mobBackoff * 2, C.S("manager_backoff_max_s"));
            }
            return;
        }
        if (planned)
        {
            planned = false;
            Simulator::Schedule(Seconds(P.opGap), &Uav::NextPlanned, this);
        }
    }

    void VideoFrame()
    {
        if (!up)
        { // nothing is sent before there is a session
            Simulator::Schedule(Seconds(1.0 / C.S("video_fps")), &Uav::VideoFrame, this);
            return;
        }
        ++frame;
        bool key = (frame % static_cast<uint32_t>(C.S("video_gop")) == 1) || forceKey;
        forceKey = false;
        double bytes = Draw(key ? "video_i_bytes" : "video_p_bytes") * P.videoScale + C.S("video_frame_hdr");
        uint32_t ck = C.S("video_chunk");
        uint32_t k = std::max<uint32_t>(1, (static_cast<uint32_t>(bytes) + ck - 1) / ck);
        uint32_t cnt = std::min<uint32_t>(250, k + P.fecParity);
        Dg d;
        d.type = VIDEO;
        d.kind = key ? 1 : 0;
        d.uav = id;
        d.frame = frame;
        d.cnt = cnt;
        d.need = std::min<uint32_t>(k, cnt);
        double spacing = C.S("uav_tx_us") * 1e-6;
        for (uint32_t i = 0; i < cnt; ++i)
        {
            d.idx = i;
            d.u = U();
            uint32_t payload = (i + 1 < k || i >= k) ? ck : std::max<uint32_t>(1, static_cast<uint32_t>(bytes) - ck * (k - 1));
            uint32_t sz = payload + C.S("rec_hdr") + C.S("video_ext") + C.S("rec_tag");
            if (P.link == "nr")
            {
                Simulator::Schedule(Seconds(i * spacing), &Net::Up, &NET, d, sz);
            }
            else
            {
                NET.Up(d, sz);
            }
        }
        ++framesSent;
        chunksSent += cnt;
        Simulator::Schedule(Seconds(1.0 / C.S("video_fps")), &Uav::VideoFrame, this);
    }
};

// ---------------------------------------------------------------------------------------------- ground station
class Gcs
{
  public:
    struct Asm
    {
        double first{0};
        std::set<uint8_t> idx;
    };
    struct Frame
    {
        uint8_t need{1};
        uint8_t got{0};
        bool key{false};
    };
    struct Vid
    {
        std::map<uint32_t, Frame> pending;
        uint32_t next{1};
        bool needKey{true};
        uint64_t complete{0}, decoded{0}, lost{0}, chunks{0};
        double lastKfReq{-10}, lastRx{0};
    };

    std::vector<double> cpuFree;
    std::map<uint64_t, Asm> hsAsm;
    std::map<uint64_t, std::pair<double, double>> answerAt; // (uav, message) -> (when the answer is ready, when it is forgotten)
    std::map<uint64_t, uint8_t> answerTx;                   // (uav, message) -> transmissions of the answer so far
    std::map<uint64_t, Asm> ctrlAsm;
    std::map<uint64_t, double> ratchetAt;                   // (uav, operation) -> when the answer is ready
    std::vector<Vid> vid;
    uint32_t ctrlSeq{0};
    double busyMs{0}, maxQueueMs{0};
    uint64_t jobs{0}, answersFromCache{0};

    static uint64_t Key(uint32_t a, uint32_t b)
    {
        return (static_cast<uint64_t>(a) << 32) | b;
    }

    // one of `gcsWorkers` threads does a job of `ms`; returns the seconds from now until it is done
    double Cpu(double ms)
    {
        size_t w = 0;
        for (size_t i = 1; i < cpuFree.size(); ++i)
        {
            if (cpuFree[i] < cpuFree[w])
            {
                w = i;
            }
        }
        double start = std::max(Now(), cpuFree[w]);
        maxQueueMs = std::max(maxQueueMs, (start - Now()) * 1000.0);
        cpuFree[w] = start + ms / 1000.0;
        busyMs += ms;
        return cpuFree[w] - Now();
    }

    void OnDgram(Dg d)
    {
        // the receive thread handles one datagram after the other: every one costs its measured time, and a request
        // is not looked at before the datagrams in front of it
        double rx = P.gcsRxCost ? C.S("gcs_rx_us") / 1000.0 : 0.0;
        if (rx > 0)
        {
            Simulator::Schedule(Seconds(Cpu(rx)), &Gcs::Handle, this, d);
        }
        else
        {
            Handle(d);
        }
    }

    void SendMsg(Dg d, uint32_t body, bool handshake, double delay)
    {
        uint32_t unit = handshake ? FragPayload() : C.S("ctrl_chunk");
        uint32_t cnt = std::max<uint32_t>(1, (body + unit - 1) / unit);
        d.cnt = cnt;
        for (uint32_t i = 0; i < cnt; ++i)
        {
            d.idx = i;
            uint32_t chunk = i + 1 < cnt ? unit : body - unit * (cnt - 1);
            uint32_t sz = handshake ? chunk + C.S("hs_hdr") : chunk + C.S("rec_hdr") + C.S("rec_tag") + (cnt > 1 ? C.S("ctrl_part_ext") : 0);
            Simulator::Schedule(Seconds(delay), &Net::Down, &NET, d, sz);
        }
    }

    void Handle(Dg d)
    {
        double host = P.link == "nr" ? C.S("host_msg_ms") / 1000.0 : 0.0;
        if (d.type == VIDEO)
        {
            Video(d);
            return;
        }
        if (d.type == CH || d.type == RKREQ)
        {
            uint64_t key = Key(d.uav, (d.type == CH ? 0x40000000u : 0x80000000u) | d.msg);
            if (d.type == CH)
            {
                // fragments of every transmission of the message meet in one place (ablation: one place per transmission)
                uint64_t akey = P.combine ? key : key ^ (static_cast<uint64_t>(d.attempt) << 52);
                Asm& a = hsAsm[akey];
                if (a.idx.empty() || Now() - a.first > C.S("reassembly_timeout_s"))
                {
                    a.idx.clear();
                    a.first = Now();
                }
                a.idx.insert(d.idx);
                if (a.idx.size() < static_cast<size_t>(d.cnt))
                {
                    return;
                }
                hsAsm.erase(akey);
            }
            Dg r;
            r.type = d.type == CH ? SH : RKRESP;
            r.uav = d.uav;
            r.msg = d.msg;
            r.op = d.op;
            r.u = d.u;
            r.attempt = P.combine ? 0 : ++answerTx[key]; // which transmission of the answer this is
            uint32_t body = d.type == CH ? PR.at("sh_bytes") : C.S("rekey_resp_bytes");
            auto it = answerAt.find(key);
            if (it != answerAt.end() && Now() < it->second.second)
            { // the same request again: the answer already made is sent again, nothing is computed twice
                ++answersFromCache;
                SendMsg(r, body, true, host + std::max(0.0, it->second.first - Now()));
                return;
            }
            double ms = d.type == CH ? Draw("gcs_full_ms") * (PR.count("scale_full_answer") ? PR["scale_full_answer"] : 1.0) : Draw("gcs_cached_ms");
            double done = Cpu(ms);
            ++jobs;
            answerAt[key] = {Now() + done, Now() + done + (d.type == CH ? C.S("hello_cache_s") : C.S("rekey_cache_s"))};
            r.aux = ms;
            SendMsg(r, body, true, host + done);
            return;
        }
        if (d.type == CTRL && d.kind == RT_REQ)
        {
            uint64_t key = Key(d.uav, d.msg);
            Asm& a = ctrlAsm[key];
            a.idx.insert(d.idx);
            if (a.idx.size() < static_cast<size_t>(d.cnt))
            {
                return;
            }
            ctrlAsm.erase(key);
            Dg r;
            r.type = CTRL;
            r.kind = RT_RESP;
            r.uav = d.uav;
            r.op = d.op;
            r.u = d.u;
            r.msg = ++ctrlSeq;
            uint64_t okey = Key(d.uav, d.op);
            auto it = ratchetAt.find(okey);
            if (it != ratchetAt.end())
            { // a repeated request gets the same answer (one new session, not two)
                ++answersFromCache;
                SendMsg(r, PR.at("ratchet_resp_bytes"), false, host + std::max(0.0, it->second - Now()));
                return;
            }
            double ms = Draw("gcs_ratchet_ms") * (PR.count("scale_ratchet_answer") ? PR["scale_ratchet_answer"] : 1.0);
            double done = Cpu(ms);
            ++jobs;
            ratchetAt[okey] = Now() + done;
            r.aux = ms;
            SendMsg(r, PR.at("ratchet_resp_bytes"), false, host + done);
        }
    }

    // Video as the receiver treats it (kyber6g/ground/video_sink.py): a frame is usable when enough of its chunks
    // arrived within the jitter window; after a frame that is not, nothing is shown until the next keyframe.
    void Video(const Dg& d)
    {
        Vid& v = vid[d.uav];
        ++v.chunks;
        v.lastRx = Now();
        if (d.frame < v.next)
        {
            return; // late
        }
        auto it = v.pending.find(d.frame);
        if (it == v.pending.end())
        {
            Frame f;
            f.need = d.need;
            f.key = d.kind & 1;
            it = v.pending.emplace(d.frame, f).first;
            Simulator::Schedule(Seconds(C.S("jitter_ms") / 1000.0), &Gcs::CheckFrame, this, d.uav, d.frame);
        }
        ++it->second.got;
    }

    void CheckFrame(uint16_t uav, uint32_t frame)
    {
        Vid& v = vid[uav];
        for (uint32_t f = v.next; f <= frame; ++f)
        {
            auto it = v.pending.find(f);
            bool ok = it != v.pending.end() && it->second.got >= it->second.need;
            if (ok)
            {
                ++v.complete;
                if (it->second.key)
                {
                    v.needKey = false;
                }
                if (!v.needKey)
                {
                    ++v.decoded;
                }
            }
            else
            {
                ++v.lost;
                v.needKey = true;
            }
            if (it != v.pending.end())
            {
                v.pending.erase(it);
            }
        }
        v.next = std::max(v.next, frame + 1);
        if (P.kfRequest && v.needKey && Now() - v.lastKfReq > 0.25)
        {
            v.lastKfReq = Now();
            Dg r;
            r.type = CTRL;
            r.kind = KF_REQ;
            r.uav = uav;
            r.u = U();
            r.msg = ++ctrlSeq;
            NET.Down(r, 60 + C.S("rec_hdr") + C.S("rec_tag"));
        }
    }
};

Gcs GCS;

// ------------------------------------------------------------------------------------------- link, both kinds
void
Net::Up(Dg d, uint32_t size)
{
    ++upSent;
    upBytes += size + C.S("udp_ip");
    if (P.link == "nr")
    {
        std::vector<uint8_t> buf(std::max<uint32_t>(size, sizeof(Dg)), 0);
        std::memcpy(buf.data(), &d, sizeof(Dg));
        uavSock[d.uav]->SendTo(Create<Packet>(buf.data(), buf.size()), 0, gcsAddr);
        return;
    }
    if (U() < P.loss)
    {
        ++upLost;
        return;
    }
    Simulator::Schedule(Seconds(TestbedDelay(d)), &Gcs::OnDgram, gcs, d);
}

void
Net::Down(Dg d, uint32_t size)
{
    ++downSent;
    downBytes += size + C.S("udp_ip");
    if (P.link == "nr")
    {
        if (!uavKnown[d.uav])
        {
            return;
        }
        std::vector<uint8_t> buf(std::max<uint32_t>(size, sizeof(Dg)), 0);
        std::memcpy(buf.data(), &d, sizeof(Dg));
        gcsSock->SendTo(Create<Packet>(buf.data(), buf.size()), 0, uavAddr[d.uav]);
        return;
    }
    if (U() < P.loss)
    {
        ++downLost;
        return;
    }
    Simulator::Schedule(Seconds(TestbedDelay(d)), &Uav::OnDgram, uavs[d.uav], d);
}

void
Net::RxGcs(Ptr<Socket> s)
{
    Address from;
    while (Ptr<Packet> p = s->RecvFrom(from))
    {
        if (p->GetSize() < sizeof(Dg))
        {
            continue;
        }
        Dg d;
        p->CopyData(reinterpret_cast<uint8_t*>(&d), sizeof(Dg));
        if (d.uav < uavAddr.size())
        {
            ++upRecv;
            uavAddr[d.uav] = from;
            uavKnown[d.uav] = true;
            gcs->OnDgram(d);
        }
    }
}

void
Net::RxUav(Ptr<Socket> s)
{
    Address from;
    while (Ptr<Packet> p = s->RecvFrom(from))
    {
        if (p->GetSize() < sizeof(Dg))
        {
            continue;
        }
        Dg d;
        p->CopyData(reinterpret_cast<uint8_t*>(&d), sizeof(Dg));
        if (d.uav < uavs.size())
        {
            ++downRecv;
            uavs[d.uav]->OnDgram(d);
        }
    }
}

// One transport block received (NR). The HARQ process sends a block up to four times (m_rv counts them, 0..3);
// a block that is still not decoded after the fourth is given up, and what it carried is lost.
void
TbTrace(bool uplink, RxPacketTraceParams p)
{
    // the library reports a block once for every packet it carries: count it once
    static uint64_t last[2] = {0, 0};
    uint64_t key = (static_cast<uint64_t>(p.m_rnti) << 48) ^ (static_cast<uint64_t>(p.m_frameNum) << 24) ^ (p.m_subframeNum << 16) ^
                   (p.m_slotNum << 8) ^ p.m_symStart;
    if (key == last[uplink])
    {
        return;
    }
    last[uplink] = key;
    uint64_t& n = uplink ? NET.ulTb : NET.dlTb;
    uint64_t& e = uplink ? NET.ulTbErr : NET.dlTbErr;
    uint64_t& l = uplink ? NET.ulTbLost : NET.dlTbLost;
    ++n;
    if (uplink)
    {
        NET.ulSinrDbSum += 10 * std::log10(p.m_sinr);
        NET.ulMcsSum += p.m_mcs;
    }
    if (p.m_corrupt)
    {
        ++e;
        if (p.m_rv == 3)
        {
            ++l;
        }
        if (P.debugPhy)
        {
            OUT << "T," << std::fixed << std::setprecision(4) << Now() << "," << (uplink ? "ul" : "dl") << "," << p.m_rnti << "," << p.m_tbSize
                << "," << +p.m_mcs << "," << +p.m_rv << "," << std::setprecision(2) << 10 * std::log10(p.m_sinr) << ","
                << 10 * std::log10(p.m_sinrMin) << "," << p.m_rbAssignedNum << "," << +p.m_numSym << "," << std::setprecision(4) << p.m_tbler
                << "\n";
        }
    }
}

// --------------------------------------------------------------------------------------------------- NR cell
struct NrScene
{
    Ptr<NrHelper> nr;
    Ptr<NrPointToPointEpcHelper> epc;
    NodeContainer gnb, ue, host;
    std::vector<double> dist;
};

NrScene
BuildNr()
{
    NrScene sc;
    Config::SetDefault("ns3::NrRlcUm::MaxTxBufferSize", UintegerValue(4 * 1024 * 1024));
    // The gNB's RRC keeps one sounding-signal index per UE context and refuses a UE when it has none left (default:
    // 40, and contexts of collided random-access attempts count until they time out). 320 is the largest setting.
    Config::SetDefault("ns3::NrGnbRrc::SrsPeriodicity", UintegerValue(320));
    Config::SetDefault("ns3::ThreeGppChannelModel::UpdatePeriod", TimeValue(MilliSeconds(P.chUpdateMs)));
    if (P.ulPowerControl)
    {
        // Uplink power control (TS 38.213, 7.1.1; open loop, full path-loss compensation): the transmit power follows
        // the number of resource blocks of the allocation, so the power per resource block - which the gNB chose the
        // modulation for - is the same for a narrow and a wide allocation. The library's default is the full power
        // spread over whatever is allocated: a UAV that was last heard on one resource-block group (the grant that
        // answers a scheduling request) is then given a modulation its full-band allocation cannot carry.
        Config::SetDefault("ns3::NrUePhy::EnableUplinkPowerControl", BooleanValue(true));
        Config::SetDefault("ns3::NrUePowerControl::ClosedLoop", BooleanValue(false));
        Config::SetDefault("ns3::NrUePowerControl::Alpha", DoubleValue(1.0));
        Config::SetDefault("ns3::NrUePowerControl::PoNominalPusch", IntegerValue(P.p0Pusch));
        Config::SetDefault("ns3::NrUePowerControl::Pcmax", DoubleValue(P.ueTx));
    }
    sc.gnb.Create(1);
    sc.ue.Create(P.nUav);

    MobilityHelper fixed;
    Ptr<ListPositionAllocator> gpos = CreateObject<ListPositionAllocator>();
    gpos->Add(Vector(0.0, 0.0, 25.0));
    fixed.SetPositionAllocator(gpos);
    fixed.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    fixed.Install(sc.gnb);

    // UAVs: uniformly over a disc around the gNB (not closer than rMin), at 60..120 m above ground
    Ptr<ListPositionAllocator> upos = CreateObject<ListPositionAllocator>();
    for (uint32_t i = 0; i < P.nUav; ++i)
    {
        double r = std::sqrt(U() * (P.radius * P.radius - P.rMin * P.rMin) + P.rMin * P.rMin);
        double a = U() * 2 * M_PI;
        double h = P.hMin + U() * (P.hMax - P.hMin);
        upos->Add(Vector(r * std::cos(a), r * std::sin(a), h));
        sc.dist.push_back(std::sqrt(r * r + (h - 25.0) * (h - 25.0)));
    }
    MobilityHelper mob;
    mob.SetPositionAllocator(upos);
    if (P.speed > 0)
    {
        std::ostringstream v;
        v << "ns3::ConstantRandomVariable[Constant=" << P.speed << "]";
        double b = P.radius + 200.0;
        mob.SetMobilityModel("ns3::GaussMarkovMobilityModel",
                             "Bounds", BoxValue(Box(-b, b, -b, b, P.hMin, P.hMax)),
                             "TimeStep", TimeValue(MilliSeconds(100)),
                             "Alpha", DoubleValue(0.85),
                             "MeanVelocity", StringValue(v.str()),
                             "MeanDirection", StringValue("ns3::UniformRandomVariable[Min=0|Max=6.283185307]"),
                             "MeanPitch", StringValue("ns3::ConstantRandomVariable[Constant=0.0]"),
                             "NormalVelocity", StringValue("ns3::NormalRandomVariable[Mean=0.0|Variance=1.0|Bound=3.0]"),
                             "NormalDirection", StringValue("ns3::NormalRandomVariable[Mean=0.0|Variance=0.2|Bound=0.4]"),
                             "NormalPitch", StringValue("ns3::NormalRandomVariable[Mean=0.0|Variance=0.02|Bound=0.04]"));
    }
    else
    {
        mob.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    }
    mob.Install(sc.ue);

    sc.epc = CreateObject<NrPointToPointEpcHelper>();
    Ptr<IdealBeamformingHelper> bf = CreateObject<IdealBeamformingHelper>();
    sc.nr = CreateObject<NrHelper>();
    sc.nr->SetBeamformingHelper(bf);
    sc.nr->SetEpcHelper(sc.epc);

    // One TDD carrier. Line of sight throughout: a UAV at 60-120 m sees the mast (the UMa line-of-sight path loss of
    // TR 38.901 is, at these heights and distances, the aerial line-of-sight formula of TR 36.777).
    CcBwpCreator cc;
    CcBwpCreator::SimpleOperationBandConf conf(P.freq, P.bw, 1, BandwidthPartInfo::UMa_LoS);
    OperationBandInfo band = cc.CreateOperationBandContiguousCc(conf);
    sc.nr->SetChannelConditionModelAttribute("UpdatePeriod", TimeValue(MilliSeconds(0)));
    sc.nr->SetPathlossAttribute("ShadowingEnabled", BooleanValue(false));
    sc.nr->InitializeOperationBand(&band);
    BandwidthPartInfoPtrVector bwps = CcBwpCreator::GetAllBwps({band});

    bf->SetAttribute("BeamformingMethod", TypeIdValue(DirectPathBeamforming::GetTypeId()));
    sc.epc->SetAttribute("S1uLinkDelay", TimeValue(MilliSeconds(0)));
    // Time-division scheduling: the gNB forms one (analog) beam at a time, towards one UAV, so the UAVs of a slot
    // take turns symbol by symbol, each over the whole band. (The library's frequency-division scheduler may put
    // UAVs of one "beam" side by side in the same symbols, and with beams computed from the direct path it takes
    // all UAVs for one beam: their blocks are then received through a beam that points elsewhere and are lost.)
    sc.nr->SetSchedulerTypeId(TypeId::LookupByName(P.scheduler == "ofdma" ? "ns3::NrMacSchedulerOfdmaPF" : "ns3::NrMacSchedulerTdmaPF"));
    sc.nr->SetUeAntennaAttribute("NumRows", UintegerValue(1));
    sc.nr->SetUeAntennaAttribute("NumColumns", UintegerValue(2));
    sc.nr->SetUeAntennaAttribute("AntennaElement", PointerValue(CreateObject<IsotropicAntennaModel>()));
    sc.nr->SetGnbAntennaAttribute("NumRows", UintegerValue(4));
    sc.nr->SetGnbAntennaAttribute("NumColumns", UintegerValue(8));
    sc.nr->SetGnbAntennaAttribute("AntennaElement", PointerValue(CreateObject<IsotropicAntennaModel>()));

    NetDeviceContainer gdev = sc.nr->InstallGnbDevice(sc.gnb, bwps);
    NetDeviceContainer udev = sc.nr->InstallUeDevice(sc.ue, bwps);
    int64_t stream = 100;
    stream += sc.nr->AssignStreams(gdev, stream);
    stream += sc.nr->AssignStreams(udev, stream);
    sc.nr->GetGnbPhy(gdev.Get(0), 0)->SetAttribute("Numerology", UintegerValue(P.numerology));
    sc.nr->GetGnbPhy(gdev.Get(0), 0)->SetAttribute("TxPower", DoubleValue(P.gnbTx));
    sc.nr->GetGnbPhy(gdev.Get(0), 0)->SetAttribute("Pattern", StringValue(P.tdd));
    sc.nr->GetGnbPhy(gdev.Get(0), 0)->GetSpectrumPhy()->TraceConnectWithoutContext("RxPacketTraceGnb", MakeBoundCallback(&TbTrace, true));
    for (uint32_t i = 0; i < udev.GetN(); ++i)
    {
        sc.nr->GetUePhy(udev.Get(i), 0)->SetAttribute("TxPower", DoubleValue(P.ueTx));
        sc.nr->GetUePhy(udev.Get(i), 0)->GetSpectrumPhy()->TraceConnectWithoutContext("RxPacketTraceUe", MakeBoundCallback(&TbTrace, false));
    }
    sc.nr->UpdateDeviceConfigs(gdev);
    sc.nr->UpdateDeviceConfigs(udev);

    // the ground station: one host behind the core network
    Ptr<Node> pgw = sc.epc->GetPgwNode();
    sc.host.Create(1);
    InternetStackHelper internet;
    internet.Install(sc.host);
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", DataRateValue(DataRate("10Gb/s")));
    p2p.SetDeviceAttribute("Mtu", UintegerValue(2500));
    p2p.SetChannelAttribute("Delay", TimeValue(MicroSeconds(static_cast<uint64_t>(P.backhaulMs * 1000))));
    NetDeviceContainer idev = p2p.Install(pgw, sc.host.Get(0));
    Ipv4AddressHelper ip;
    ip.SetBase("1.0.0.0", "255.0.0.0");
    Ipv4InterfaceContainer ifc = ip.Assign(idev);
    Ipv4StaticRoutingHelper rh;
    rh.GetStaticRouting(sc.host.Get(0)->GetObject<Ipv4>())->AddNetworkRouteTo(Ipv4Address("7.0.0.0"), Ipv4Mask("255.0.0.0"), 1);
    internet.Install(sc.ue);
    sc.epc->AssignUeIpv4Address(udev);
    for (uint32_t i = 0; i < sc.ue.GetN(); ++i)
    {
        rh.GetStaticRouting(sc.ue.Get(i)->GetObject<Ipv4>())->SetDefaultRoute(sc.epc->GetUeDefaultGatewayAddress(), 1);
    }
    sc.nr->AttachToClosestGnb(udev, gdev);

    const uint16_t port = 14600;
    NET.gcsSock = Socket::CreateSocket(sc.host.Get(0), UdpSocketFactory::GetTypeId());
    NET.gcsSock->Bind(InetSocketAddress(Ipv4Address::GetAny(), port));
    NET.gcsSock->SetRecvCallback(MakeCallback(&Net::RxGcs, &NET));
    NET.gcsAddr = InetSocketAddress(ifc.GetAddress(1), port);
    for (uint32_t i = 0; i < sc.ue.GetN(); ++i)
    {
        Ptr<Socket> s = Socket::CreateSocket(sc.ue.Get(i), UdpSocketFactory::GetTypeId());
        s->Bind();
        s->SetRecvCallback(MakeCallback(&Net::RxUav, &NET));
        NET.uavSock.push_back(s);
    }
    return sc;
}

} // namespace

int
main(int argc, char* argv[])
{
    uint32_t run = 1;
    CommandLine cmd(__FILE__);
    cmd.AddValue("link", "testbed (calibrated replica of the test bed) or nr (5G NR cell)", P.link);
    cmd.AddValue("profile", "cryptographic configuration: hybrid5 (implemented), pq5, hybrid3, hybrid1, classical", P.profile);
    cmd.AddValue("calib", "calibration file written by simulation/calibrate.py", P.calib);
    cmd.AddValue("out", "output file", P.out);
    cmd.AddValue("tag", "free text copied into the output", P.tag);
    cmd.AddValue("nUav", "number of UAVs", P.nUav);
    cmd.AddValue("simTime", "simulated seconds", P.simTime);
    cmd.AddValue("loss", "datagram loss probability in each direction (test-bed link)", P.loss);
    cmd.AddValue("opsPerUav", "operations of each kind per UAV", P.opsPerUav);
    cmd.AddValue("opGap", "seconds between two operations of a UAV", P.opGap);
    cmd.AddValue("ops", "kinds of operation to run: any of full,cached,ratchet", P.ops);
    cmd.AddValue("storm", "all UAVs start their first handshake at the same instant", P.storm);
    cmd.AddValue("video", "every UAV sends its video stream", P.video);
    cmd.AddValue("videoScale", "video frame size relative to the measured stream", P.videoScale);
    cmd.AddValue("fecParity", "design study: parity chunks per video frame", P.fecParity);
    cmd.AddValue("kfRequest", "design study: keyframe request after a lost frame", P.kfRequest);
    cmd.AddValue("retxScale", "design study: repeat intervals times this", P.retxScale);
    cmd.AddValue("adaptiveRetx", "design study: repeat after 3 x the last unrepeated round trip, at most the fixed timer", P.adaptiveRetx);
    cmd.AddValue("combine", "fragments of repeated handshake messages combine (1, as implemented) or not (0)", P.combine);
    cmd.AddValue("gcsWorkers", "design study: request-handling threads at the ground station", P.gcsWorkers);
    cmd.AddValue("gcsRxCost", "every datagram costs the ground station's receive thread its measured time", P.gcsRxCost);
    cmd.AddValue("fragPayload", "design study: handshake fragment payload in bytes (0 = as implemented)", P.fragPayload);
    cmd.AddValue("freq", "NR carrier frequency (Hz)", P.freq);
    cmd.AddValue("bw", "NR bandwidth (Hz)", P.bw);
    cmd.AddValue("numerology", "NR numerology", P.numerology);
    cmd.AddValue("tdd", "NR TDD pattern", P.tdd);
    cmd.AddValue("gnbTx", "gNB transmit power (dBm)", P.gnbTx);
    cmd.AddValue("ueTx", "UAV transmit power (dBm)", P.ueTx);
    cmd.AddValue("radius", "UAVs are placed within this distance of the gNB (m)", P.radius);
    cmd.AddValue("rMin", "... and not closer than this (m)", P.rMin);
    cmd.AddValue("speed", "UAV speed (m/s), 0 = hovering", P.speed);
    cmd.AddValue("backhaulMs", "one-way delay between the core network and the ground station (ms)", P.backhaulMs);
    cmd.AddValue("chUpdateMs", "NR channel update period (ms), 0 = never", P.chUpdateMs);
    cmd.AddValue("cellHandshake", "a moving UAV makes a full handshake when it enters another position cell (as implemented)", P.cellHandshake);
    cmd.AddValue("scheduler", "NR: tdma (proportional fair, one UAV at a time over the whole band) or ofdma", P.scheduler);
    cmd.AddValue("ulPowerControl", "NR: uplink power control of TS 38.213 (0 = fixed total power, the library's default)", P.ulPowerControl);
    cmd.AddValue("p0", "NR: target received power per resource block of the uplink power control (dBm)", P.p0Pusch);
    cmd.AddValue("debugPhy", "NR: write one line per transport block that was not decoded", P.debugPhy);
    cmd.AddValue("run", "run number (independent random streams)", run);
    cmd.Parse(argc, argv);

    RngSeedManager::SetSeed(20261004);
    RngSeedManager::SetRun(run);
    RNG = CreateObject<UniformRandomVariable>();
    RNG->SetStream(7);
    C.Load(P.calib);
    NS_ABORT_MSG_IF(!C.profile.count(P.profile), "the calibration file has no configuration '" << P.profile << "'");
    PR = C.profile[P.profile];
    NS_ABORT_MSG_IF(P.link != "testbed" && P.link != "nr", "--link must be testbed or nr");
    if (P.link == "testbed" && P.nUav != 1)
    {
        std::cerr << "note: the test-bed link was measured with ONE UAV; more than one share nothing but the ground station here\n";
    }

    OUT.open(P.out);
    NS_ABORT_MSG_IF(!OUT, "cannot write " << P.out);
    OUT << "# k6g-swarm-sim " << P.tag << "\n";
    OUT << "# O,uav,op,kind,initial,t0_s,ok,total_ms,build_ms,wait_ms,process_ms,finish_ms,gcs_ms,transmissions,why\n";
    OUT << "#   initial: 1 = the UAV's first handshake, 2 = handshake after a change of position cell, 0 = planned operation\n";
    OUT << "# V,uav,frames_sent,frames_complete,frames_decoded,frames_lost,chunks_received,key_requests,distance_m,chunks_sent,last_rx_s,"
           "cell_changes\n";
    if (P.debugPhy)
    {
        OUT << "# T,t_s,dir,rnti,tb_bytes,mcs,transmission,sinr_avg_dB,sinr_min_dB,rb,symbols,tbler\n";
    }

    std::vector<Uav> uavs(P.nUav);
    NET.gcs = &GCS;
    GCS.cpuFree.assign(std::max<uint32_t>(1, P.gcsWorkers), 0.0);
    GCS.vid.resize(P.nUav);
    NET.uavAddr.resize(P.nUav);
    NET.uavKnown.assign(P.nUav, false);
    for (uint32_t i = 0; i < P.nUav; ++i)
    {
        uavs[i].id = i;
        uavs[i].backoff = uavs[i].mobBackoff = C.S("manager_backoff_s");
        NET.uavs.push_back(&uavs[i]);
    }
    NrScene sc;
    if (P.link == "nr")
    {
        sc = BuildNr();
        for (uint32_t i = 0; i < P.nUav; ++i)
        {
            uavs[i].mm = sc.ue.Get(i)->GetObject<MobilityModel>();
        }
    }

    std::vector<int> kinds;
    if (P.ops.find("full") != std::string::npos)
    {
        kinds.push_back(FULL);
    }
    if (P.ops.find("cached") != std::string::npos)
    {
        kinds.push_back(CACHED);
    }
    if (P.ops.find("ratchet") != std::string::npos)
    {
        kinds.push_back(RATCHET);
    }
    const double tInit = 2.0; // every UAV has joined the cell by then (random access, also after collisions)
    const double tOps = 3.5;
    for (auto& u : uavs)
    {
        // first: the session (a full handshake); with --storm all at the same instant, otherwise spread over half a second
        Simulator::Schedule(Seconds(tInit + (P.storm ? 0.0 : U() * 0.5)), &Uav::StartOp, &u, static_cast<int>(FULL));
        if (u.mm && P.speed > 0 && P.cellHandshake)
        { // the position cell is known before the first handshake, which is made in it
            Simulator::Schedule(Seconds(tInit - 0.5), &Uav::CellTick, &u);
        }
        if (P.video)
        {
            Simulator::Schedule(Seconds(tOps - 0.5 + U() / 30.0), &Uav::VideoFrame, &u);
        }
        for (uint32_t r = 0; r < P.opsPerUav; ++r)
        {
            for (int k : kinds)
            {
                u.plan.push_back(k);
            }
        }
        if (!u.plan.empty())
        {
            Simulator::Schedule(Seconds(tOps + U() * P.opGap), &Uav::NextPlanned, &u);
        }
    }
    Simulator::Stop(Seconds(P.simTime));
    Simulator::Run();

    uint64_t sent = 0, complete = 0, decoded = 0;
    for (auto& u : uavs)
    {
        const auto& v = GCS.vid[u.id];
        // frames still inside the jitter window at the end are not judged: only what was checked is counted
        OUT << "V," << u.id << "," << u.framesSent << "," << v.complete << "," << v.decoded << "," << v.lost << "," << v.chunks << "," << u.keyRequests
            << "," << std::setprecision(1) << (P.link == "nr" ? sc.dist[u.id] : 0.0) << "," << u.chunksSent << "," << std::setprecision(4)
            << v.lastRx << "," << u.cellChanges << "\n";
        sent += u.framesSent;
        complete += v.complete;
        decoded += v.decoded;
    }
    std::string tdd = P.tdd;
    std::replace(tdd.begin(), tdd.end(), '|', '.'); // the line is a list of key=value separated by commas
    OUT << std::setprecision(4) << "M,link=" << P.link << ",profile=" << P.profile << ",nUav=" << P.nUav << ",run=" << run << ",loss=" << P.loss
        << ",speed=" << P.speed << ",simTime=" << P.simTime << ",storm=" << P.storm << ",video=" << P.video << ",fecParity=" << P.fecParity
        << ",kfRequest=" << P.kfRequest << ",retxScale=" << P.retxScale << ",adaptiveRetx=" << P.adaptiveRetx << ",combine=" << P.combine
        << ",gcsWorkers=" << P.gcsWorkers
        << ",fragPayload=" << FragPayload() << ",bw=" << P.bw << ",radius=" << P.radius << ",rMin=" << P.rMin << ",chUpdateMs=" << P.chUpdateMs
        << ",videoScale=" << P.videoScale << ",tdd=" << tdd
        << ",scheduler=" << P.scheduler << ",ulPowerControl=" << P.ulPowerControl << ",upSent=" << NET.upSent << ",upLost=" << NET.upLost << ",upRecv=" << NET.upRecv
        << ",downSent=" << NET.downSent << ",downLost=" << NET.downLost << ",downRecv=" << NET.downRecv << ",upBytes=" << NET.upBytes
        << ",downBytes=" << NET.downBytes << ",ulTb=" << NET.ulTb << ",ulTbErr=" << NET.ulTbErr << ",ulTbLost=" << NET.ulTbLost << ",dlTb="
        << NET.dlTb << ",dlTbErr=" << NET.dlTbErr << ",dlTbLost=" << NET.dlTbLost << ",ulSinrMeanDb="
        << (NET.ulTb ? NET.ulSinrDbSum / NET.ulTb : 0.0) << ",ulMcsMean=" << (NET.ulTb ? NET.ulMcsSum / NET.ulTb : 0.0) << ",gcsBusyMs="
        << GCS.busyMs << ",gcsMaxQueueMs="
        << GCS.maxQueueMs << ",gcsJobs=" << GCS.jobs << ",gcsCacheAnswers=" << GCS.answersFromCache << ",framesSent=" << sent
        << ",framesComplete=" << complete << ",framesDecoded=" << decoded << "\n";
    OUT.close();
    Simulator::Destroy();
    return 0;
}
