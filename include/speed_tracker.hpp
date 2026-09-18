#pragma once

#include "utils.hpp"

#include <string>
#include <unordered_map>
#include <vector>

namespace ntrack {

struct InterfaceStats {
    std::string name;
    uint64_t rx_bytes = 0;
    uint64_t tx_bytes = 0;
    uint64_t rx_packets = 0;
    uint64_t tx_packets = 0;
    bool is_up = false;
};

struct SpeedSnapshot {
    std::string interface;
    double download_bps = 0.0;  // bytes/sec
    double upload_bps = 0.0;
    uint64_t total_rx = 0;
    uint64_t total_tx = 0;
    bool is_up = false;
};

class SpeedTracker {
public:
    // Collect current counters for all non-loopback interfaces (or a filter).
    static std::vector<InterfaceStats> collect_interfaces();

    // Feed a new sample; returns per-interface rates once two samples exist.
    std::vector<SpeedSnapshot> update();

    SpeedSnapshot totals() const { return totals_; }

private:
    std::unordered_map<std::string, Sample> previous_;
    SpeedSnapshot totals_;
};

}  // namespace ntrack
