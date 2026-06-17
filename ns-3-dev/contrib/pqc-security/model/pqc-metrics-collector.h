/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#ifndef PQC_METRICS_COLLECTOR_H
#define PQC_METRICS_COLLECTOR_H

#include "ns3/nstime.h"
#include "ns3/object.h"
#include "ns3/type-id.h"

#include <cmath>
#include <cstdint>
#include <fstream>
#include <map>
#include <string>
#include <vector>

namespace ns3
{
namespace pqc
{

/**
 * \brief Central metrics collection and CSV export for PQC experiments.
 *
 * Aggregates all PQC-related trace data and provides statistical
 * summaries (mean, p50, p95, p99, stddev) and CSV export
 * for publication-ready data.
 */
class PqcMetricsCollector : public Object
{
  public:
    static TypeId GetTypeId();

    PqcMetricsCollector();
    ~PqcMetricsCollector() override;

    // ═══════════════════════════════════════════════════
    // Recording methods (called by trace callbacks)
    // ═══════════════════════════════════════════════════

    /// Control plane overhead
    void RecordRrcRequestSize(uint32_t bytes);
    void RecordRrcSetupSize(uint32_t bytes);
    void RecordPdcpHeaderOverhead(uint32_t originalSize, uint32_t encryptedSize);

    /// Latency metrics
    void RecordRrcSetupLatency(Time latency);
    void RecordKeyGenLatency(Time latency);
    void RecordEncapsLatency(Time latency);
    void RecordDecapsLatency(Time latency);
    void RecordAuthSignLatency(Time latency);
    void RecordAuthVerifyLatency(Time latency);
    void RecordHandshakeLatency(Time latency);
    void RecordE2eApplicationLatency(Time latency);
    void RecordQueueingDelay(Time delay);

    /// Application Performance metrics
    void RecordThroughputBytes(uint32_t bytes);
    void RecordPacketLoss();
    void RecordPacketSent();
    void RecordPacketReceived();

    /// Handover metrics
    void RecordHandoverInterruptionTime(Time hit);
    void RecordHandoverRekeyTime(Time rekeyTime);
    void RecordHandoverCount(uint32_t count);
    void RecordHandoverFailure();

    /// Fragmentation metrics
    void RecordRlcSegmentation(uint32_t originalPduSize, uint32_t numSegments);

    /// Packet-level encryption metrics
    void RecordEncryptionLatency(Time latency);
    void RecordDecryptionLatency(Time latency);

    /// Energy and Resource usage
    void RecordCryptoEnergyMicroJoules(double energy);
    void RecordCryptoMemoryBytes(uint32_t memory);

    /// Evaluation Metrics
    void RecordSecurityScore(double score);
    void RecordEfficiencyScore(double score);
    void RecordCryptoComputationTime(Time t);

    void RecordHandoffLatencyMs(double ms);
    void RecordCryptoComputeEnergyMj(double mj);
    void RecordTxEnergyMj(double mj);
    void RecordRxEnergyMj(double mj);
    void RecordIdleEnergyMj(double mj);
    void RecordMemoryEnergyMj(double mj);
    void RecordTotalEnergyMj(double mj);
    void RecordEstimatedBatteryLifeMinutes(double minutes);
    void RecordCacheHitRate(double rate);
    void RecordStaleKeyEvent(uint32_t count);
    void RecordRevokedKeyReuseAttempt(uint32_t count);
    void RecordSecurityBitsClassical(double bits);
    void RecordSecurityBitsQuantum(double bits);
    void RecordAttackCostLog2Ops(double log2ops);
    void RecordThroughputMbps(double mbps);

    /**
     * \brief Compute 95% confidence interval half-width (t-distribution).
     * \param mean Sample mean
     * \param stddev Sample standard deviation
     * \param n Sample count
     * \param alpha Significance level (default 0.05 for 95% CI)
     */
    static double ComputeConfidenceIntervalHalfWidth(double mean,
                                                     double stddev,
                                                     uint32_t n,
                                                     double alpha = 0.05);

    void ExportMetadataJson(const std::string& filename,
                            const std::map<std::string, std::string>& meta) const;

    // ═══════════════════════════════════════════════════
    // Retrieval and export
    // ═══════════════════════════════════════════════════

    /**
     * \brief Export all metrics to a CSV file.
     * \param filename Output CSV file path.
     */
    void ExportToCsv(const std::string& filename);

    /**
     * \brief Print a summary of all metrics to the NS-3 log.
     */
    void PrintSummary();

    /**
     * \brief Export specific intermediate logs for Python orchestration.
     */
    void ExportIntermediateLogs(const std::string& directory);
    
    /**
     * \brief Set the number of drone nodes for physical layer abstraction penalty scaling.
     */
    void SetNodeCount(uint32_t nodes) { m_nodeCount = nodes; }

    /**
     * \brief Get the statistical summary for a named metric.
     */
    struct MetricStats
    {
        double mean{0};
        double stddev{0};
        double min{0};
        double max{0};
        double p50{0};
        double p95{0};
        double p99{0};
        uint32_t count{0};
    };

    MetricStats GetStats(const std::string& metricName) const;

  private:
    /// Internal representation of a metric time series
    struct MetricSeries
    {
        std::vector<std::pair<Time, double>> samples;

        void Add(Time t, double value)
        {
            samples.push_back({t, value});
        }

        double Mean() const
        {
            if (samples.empty())
                return 0;
            double sum = 0;
            for (const auto& s : samples)
                sum += s.second;
            return sum / samples.size();
        }

        double StdDev() const
        {
            if (samples.size() < 2)
                return 0;
            double m = Mean();
            double sumSq = 0;
            for (const auto& s : samples)
                sumSq += (s.second - m) * (s.second - m);
            return std::sqrt(sumSq / (samples.size() - 1));
        }

        double Percentile(double p) const
        {
            if (samples.empty())
                return 0;
            std::vector<double> vals;
            vals.reserve(samples.size());
            for (const auto& s : samples)
                vals.push_back(s.second);
            std::sort(vals.begin(), vals.end());
            size_t idx = static_cast<size_t>(p / 100.0 * (vals.size() - 1));
            return vals[std::min(idx, vals.size() - 1)];
        }

        double Min() const
        {
            if (samples.empty())
                return 0;
            double m = samples[0].second;
            for (const auto& s : samples)
                m = std::min(m, s.second);
            return m;
        }

        double Max() const
        {
            if (samples.empty())
                return 0;
            double m = samples[0].second;
            for (const auto& s : samples)
                m = std::max(m, s.second);
            return m;
        }
    };

    std::map<std::string, MetricSeries> m_metrics;
    uint32_t m_nodeCount{10};

    void Record(const std::string& name, double value);
};

} // namespace pqc
} // namespace ns3

#endif // PQC_METRICS_COLLECTOR_H
