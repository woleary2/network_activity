#pragma once

#include "activity_monitor.hpp"
#include "speed_tracker.hpp"

#include <chrono>
#include <deque>
#include <string>
#include <unordered_map>
#include <vector>

namespace ntrack {

enum class ThreatLevel { Info, Low, Medium, High, Critical };

struct ThreatEvent {
    ThreatLevel level = ThreatLevel::Info;
    std::string category;
    std::string message;
    std::chrono::system_clock::time_point time;
};

class ThreatDetector {
public:
    struct Config {
        double upload_spike_bps = 5.0 * 1024 * 1024;      // 5 MiB/s
        double download_spike_bps = 50.0 * 1024 * 1024;   // 50 MiB/s
        size_t max_new_connections_per_interval = 40;
        size_t max_unique_remotes = 80;
        double sustained_upload_bps = 2.0 * 1024 * 1024;  // 2 MiB/s
        int sustained_upload_secs = 30;
    };

    ThreatDetector();
    explicit ThreatDetector(Config cfg);

    std::vector<ThreatEvent> evaluate(const SpeedSnapshot& speeds,
                                      const ActivitySummary& activity);

    const std::vector<ThreatEvent>& history() const { return history_; }
    const std::vector<ThreatEvent>& latest() const { return latest_; }

    static const char* level_name(ThreatLevel level);
    static const char* level_color(ThreatLevel level);

private:
    Config cfg_;
    std::vector<ThreatEvent> history_;
    std::vector<ThreatEvent> latest_;

    size_t prev_established_ = 0;
    std::deque<double> upload_history_;
    std::chrono::steady_clock::time_point upload_high_since_{};
    bool upload_high_active_ = false;

    std::unordered_map<uint16_t, std::string> suspicious_ports_;
    std::unordered_map<uint16_t, std::string> risky_listen_ports_;

    void push(ThreatLevel level, const std::string& category,
              const std::string& message);
    void init_port_lists();
};

}  // namespace ntrack
