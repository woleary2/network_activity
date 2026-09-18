#include "threat_detector.hpp"

#include "utils.hpp"

#include <sstream>

namespace ntrack {

ThreatDetector::ThreatDetector() : ThreatDetector(Config{}) {}

ThreatDetector::ThreatDetector(Config cfg) : cfg_(std::move(cfg)) {
    init_port_lists();
}

void ThreatDetector::init_port_lists() {
    // Common malware / C2 / abuse ports (heuristic — not definitive).
    suspicious_ports_ = {
        {4444, "Metasploit default"},
        {5555, "Android Debug / abuse"},
        {6666, "IRC botnet common"},
        {6667, "IRC"},
        {31337, "Back Orifice / elite"},
        {12345, "NetBus"},
        {27374, "SubSeven"},
        {65535, "high ephemeral abuse"},
        {1337, "leet / common reverse shell"},
        {4443, "TLS abuse alternate"},
        {8081, "proxy / malware panel common"},
        {9050, "Tor SOCKS"},
        {9051, "Tor control"},
    };

    risky_listen_ports_ = {
        {23, "Telnet (unencrypted remote access)"},
        {135, "MSRPC"},
        {139, "NetBIOS"},
        {445, "SMB"},
        {3389, "RDP"},
        {5900, "VNC"},
        {6379, "Redis (often exposed)"},
        {27017, "MongoDB (often exposed)"},
        {11211, "Memcached"},
    };
}

const char* ThreatDetector::level_name(ThreatLevel level) {
    switch (level) {
        case ThreatLevel::Info: return "INFO";
        case ThreatLevel::Low: return "LOW";
        case ThreatLevel::Medium: return "MEDIUM";
        case ThreatLevel::High: return "HIGH";
        case ThreatLevel::Critical: return "CRITICAL";
    }
    return "INFO";
}

const char* ThreatDetector::level_color(ThreatLevel level) {
    switch (level) {
        case ThreatLevel::Info: return term::cyan;
        case ThreatLevel::Low: return term::blue;
        case ThreatLevel::Medium: return term::yellow;
        case ThreatLevel::High: return term::magenta;
        case ThreatLevel::Critical: return term::red;
    }
    return term::reset;
}

void ThreatDetector::push(ThreatLevel level, const std::string& category,
                          const std::string& message) {
    ThreatEvent ev;
    ev.level = level;
    ev.category = category;
    ev.message = message;
    ev.time = std::chrono::system_clock::now();
    latest_.push_back(ev);
    history_.push_back(ev);
    if (history_.size() > 100) {
        history_.erase(history_.begin(),
                       history_.begin() +
                           static_cast<std::ptrdiff_t>(history_.size() - 100));
    }
}

std::vector<ThreatEvent> ThreatDetector::evaluate(
    const SpeedSnapshot& speeds, const ActivitySummary& activity) {
    latest_.clear();
    const auto now = std::chrono::steady_clock::now();

    // --- Bandwidth spikes ---
    if (speeds.upload_bps >= cfg_.upload_spike_bps) {
        std::ostringstream oss;
        oss << "Upload spike " << format_rate(speeds.upload_bps)
            << " (threshold " << format_rate(cfg_.upload_spike_bps) << ")";
        push(ThreatLevel::High, "exfiltration", oss.str());
    }
    if (speeds.download_bps >= cfg_.download_spike_bps) {
        std::ostringstream oss;
        oss << "Download spike " << format_rate(speeds.download_bps)
            << " (threshold " << format_rate(cfg_.download_spike_bps) << ")";
        push(ThreatLevel::Medium, "bandwidth", oss.str());
    }

    // --- Sustained high upload (possible data leak) ---
    upload_history_.push_back(speeds.upload_bps);
    while (upload_history_.size() > 60) upload_history_.pop_front();

    if (speeds.upload_bps >= cfg_.sustained_upload_bps) {
        if (!upload_high_active_) {
            upload_high_active_ = true;
            upload_high_since_ = now;
        } else {
            const auto held = std::chrono::duration_cast<std::chrono::seconds>(
                now - upload_high_since_);
            if (held.count() >= cfg_.sustained_upload_secs) {
                std::ostringstream oss;
                oss << "Sustained upload " << format_rate(speeds.upload_bps)
                    << " for " << held.count() << "s";
                push(ThreatLevel::Critical, "exfiltration", oss.str());
            }
        }
    } else {
        upload_high_active_ = false;
    }

    // --- Connection churn ---
    if (prev_established_ > 0) {
        const size_t current = activity.established;
        size_t delta = 0;
        if (current > prev_established_) {
            delta = current - prev_established_;
        }
        if (delta >= cfg_.max_new_connections_per_interval) {
            std::ostringstream oss;
            oss << "+" << delta << " new established connections this interval";
            push(ThreatLevel::Medium, "scan/churn", oss.str());
        }
    }
    prev_established_ = activity.established;

    if (activity.unique_remotes >= cfg_.max_unique_remotes) {
        std::ostringstream oss;
        oss << activity.unique_remotes
            << " unique remote hosts (possible scan or P2P)";
        push(ThreatLevel::Medium, "fan-out", oss.str());
    }

    // --- Suspicious remote / listen ports ---
    for (const auto& c : activity.connections) {
        if (c.state == "LISTEN") {
            auto it = risky_listen_ports_.find(c.local_port);
            if (it != risky_listen_ports_.end()) {
                std::ostringstream oss;
                oss << "Listening on " << c.local_port << " (" << it->second
                    << ") via " << c.process;
                push(ThreatLevel::High, "exposure", oss.str());
            }
        }

        if (c.remote_port != 0) {
            auto it = suspicious_ports_.find(c.remote_port);
            if (it != suspicious_ports_.end()) {
                std::ostringstream oss;
                oss << c.process << " -> " << c.remote_addr << ":"
                    << c.remote_port << " (" << it->second << ")";
                push(ThreatLevel::High, "suspicious-port", oss.str());
            }
        }

        // Outbound to high ports with ESTABLISHED from unusual local processes
        // is too noisy; skip generic high-port checks.
    }

    // Deduplicate identical messages in this tick
    std::vector<ThreatEvent> unique;
    unique.reserve(latest_.size());
    for (const auto& ev : latest_) {
        bool seen = false;
        for (const auto& u : unique) {
            if (u.category == ev.category && u.message == ev.message) {
                seen = true;
                break;
            }
        }
        if (!seen) unique.push_back(ev);
    }
    latest_ = unique;
    return unique;
}

}  // namespace ntrack
