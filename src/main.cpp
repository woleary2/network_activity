#include "activity_monitor.hpp"
#include "speed_tracker.hpp"
#include "threat_detector.hpp"
#include "utils.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

std::atomic<bool> g_running{true};

void on_signal(int) { g_running = false; }

struct Options {
    double interval_sec = 1.0;
    bool once = false;
    bool no_color = false;
    size_t max_connections = 12;
    size_t max_threats = 8;
    double upload_spike_mib = 5.0;
    double download_spike_mib = 50.0;
};

void print_usage(const char* argv0) {
    std::cout
        << "Network Track — live upload/download, activity, and threat monitor\n\n"
        << "Usage: " << argv0 << " [options]\n\n"
        << "Options:\n"
        << "  -i, --interval SEC   Sample interval (default: 1.0)\n"
        << "  -n, --once           Single sample then exit\n"
        << "  -c, --connections N  Max connections to display (default: 12)\n"
        << "  -t, --threats N      Max threat events to display (default: 8)\n"
        << "      --upload-mib N   Upload spike threshold MiB/s (default: 5)\n"
        << "      --download-mib N Download spike threshold MiB/s (default: 50)\n"
        << "      --no-color       Disable ANSI colors\n"
        << "  -h, --help           Show this help\n";
}

bool parse_args(int argc, char** argv, Options& opt) {
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto need = [&](const char* name) -> std::string {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for " << name << "\n";
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "-h" || a == "--help") {
            print_usage(argv[0]);
            std::exit(0);
        } else if (a == "-i" || a == "--interval") {
            opt.interval_sec = std::stod(need(a.c_str()));
        } else if (a == "-n" || a == "--once") {
            opt.once = true;
        } else if (a == "-c" || a == "--connections") {
            opt.max_connections = static_cast<size_t>(std::stoul(need(a.c_str())));
        } else if (a == "-t" || a == "--threats") {
            opt.max_threats = static_cast<size_t>(std::stoul(need(a.c_str())));
        } else if (a == "--upload-mib") {
            opt.upload_spike_mib = std::stod(need(a.c_str()));
        } else if (a == "--download-mib") {
            opt.download_spike_mib = std::stod(need(a.c_str()));
        } else if (a == "--no-color") {
            opt.no_color = true;
        } else {
            std::cerr << "Unknown option: " << a << "\n";
            print_usage(argv[0]);
            return false;
        }
    }
    if (opt.interval_sec < 0.2) opt.interval_sec = 0.2;
    return true;
}

std::string cwrap(bool enable, const char* code, const std::string& text) {
    if (!enable) return text;
    return std::string(code) + text + ntrack::term::reset;
}

std::string bar(double bps, double scale, int width, bool color_on,
                const char* color) {
    if (scale <= 0) scale = 1;
    int filled = static_cast<int>((bps / scale) * width);
    if (filled < 0) filled = 0;
    if (filled > width) filled = width;
    std::string s(filled, '|');
    s.append(static_cast<size_t>(width - filled), '.');
    return cwrap(color_on, color, s);
}

void render(const Options& opt, bool color_on,
            const std::vector<ntrack::SpeedSnapshot>& ifaces,
            const ntrack::SpeedSnapshot& totals,
            const ntrack::ActivitySummary& activity,
            const std::vector<ntrack::ThreatEvent>& threats,
            std::chrono::seconds uptime) {
    if (color_on && !opt.once) {
        std::cout << ntrack::term::clear;
    }

    std::cout << cwrap(color_on, ntrack::term::bold,
                       "Network Track")
              << cwrap(color_on, ntrack::term::dim, "  ·  live monitor  ·  ")
              << "uptime " << ntrack::format_duration(uptime) << "\n\n";

    // Speeds
    std::cout << cwrap(color_on, ntrack::term::bold, "Throughput") << "\n";
    const double scale =
        std::max(1.0, std::max(totals.download_bps, totals.upload_bps) * 1.25);
    std::cout << "  ↓ down  "
              << cwrap(color_on, ntrack::term::green,
                       ntrack::format_rate(totals.download_bps))
              << "  "
              << bar(totals.download_bps, scale, 28, color_on,
                     ntrack::term::green)
              << "\n";
    std::cout << "  ↑ up    "
              << cwrap(color_on, ntrack::term::cyan,
                       ntrack::format_rate(totals.upload_bps))
              << "  "
              << bar(totals.upload_bps, scale, 28, color_on, ntrack::term::cyan)
              << "\n";
    std::cout << cwrap(color_on, ntrack::term::dim,
                       "  totals  rx " + ntrack::format_bytes(totals.total_rx) +
                           "  tx " + ntrack::format_bytes(totals.total_tx))
              << "\n\n";

    if (!ifaces.empty()) {
        std::cout << cwrap(color_on, ntrack::term::bold, "Interfaces") << "\n";
        for (const auto& s : ifaces) {
            const char* status =
                s.is_up ? (color_on ? "\033[32mup\033[0m" : "up")
                        : (color_on ? "\033[2mdown\033[0m" : "down");
            std::cout << "  " << std::left << std::setw(10) << s.interface
                      << " " << status << "  ↓ "
                      << std::setw(12) << ntrack::format_rate(s.download_bps)
                      << " ↑ " << std::setw(12)
                      << ntrack::format_rate(s.upload_bps) << "\n";
        }
        std::cout << "\n";
    }

    // Activity
    std::cout << cwrap(color_on, ntrack::term::bold, "Activity") << "  "
              << cwrap(color_on, ntrack::term::dim,
                       "tcp " + std::to_string(activity.tcp_total) + "  udp " +
                           std::to_string(activity.udp_total) + "  est " +
                           std::to_string(activity.established) + "  listen " +
                           std::to_string(activity.listening) + "  remotes " +
                           std::to_string(activity.unique_remotes))
              << "\n";

    size_t shown = 0;
    for (const auto& c : activity.connections) {
        if (shown >= opt.max_connections) break;
        // Prefer interesting rows
        if (c.state != "ESTABLISHED" && c.state != "LISTEN" &&
            c.state != "CONN" && shown > 3) {
            continue;
        }
        std::ostringstream line;
        line << (c.proto == ntrack::Proto::Tcp ? "TCP" : "UDP") << " "
             << c.local_addr << ":" << c.local_port << " -> "
             << c.remote_addr << ":" << c.remote_port << "  [" << c.state
             << "]  " << c.process;
        if (c.pid > 0) line << " (" << c.pid << ")";

        const char* stcolor = ntrack::term::dim;
        if (c.state == "ESTABLISHED") stcolor = ntrack::term::green;
        else if (c.state == "LISTEN") stcolor = ntrack::term::yellow;

        std::cout << "  " << cwrap(color_on, stcolor, line.str()) << "\n";
        ++shown;
    }
    if (activity.connections.empty()) {
        std::cout << cwrap(color_on, ntrack::term::dim,
                           "  (no socket data — try running without sandbox "
                           "restrictions)")
                  << "\n";
    }
    std::cout << "\n";

    // Threats
    std::cout << cwrap(color_on, ntrack::term::bold, "Threats") << "\n";
    if (threats.empty()) {
        std::cout << "  "
                  << cwrap(color_on, ntrack::term::green, "clear")
                  << cwrap(color_on, ntrack::term::dim,
                           " — no heuristics fired this interval")
                  << "\n";
    } else {
        size_t n = 0;
        for (const auto& t : threats) {
            if (n >= opt.max_threats) break;
            std::ostringstream head;
            head << "[" << ntrack::ThreatDetector::level_name(t.level) << "] "
                 << t.category;
            std::cout << "  "
                      << cwrap(color_on,
                               ntrack::ThreatDetector::level_color(t.level),
                               head.str())
                      << "  " << t.message << "\n";
            ++n;
        }
    }

    std::cout << "\n"
              << cwrap(color_on, ntrack::term::dim, "Ctrl+C to quit")
              << std::endl;
}

}  // namespace

int main(int argc, char** argv) {
    Options opt;
    if (!parse_args(argc, argv, opt)) return 2;

    const bool color_on = !opt.no_color && ntrack::term::is_tty();

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    if (color_on && !opt.once) {
        std::cout << ntrack::term::hide_cursor;
    }

    ntrack::SpeedTracker speeds;
    ntrack::ActivityMonitor activity;
    ntrack::ThreatDetector::Config tcfg;
    tcfg.upload_spike_bps = opt.upload_spike_mib * 1024.0 * 1024.0;
    tcfg.download_spike_bps = opt.download_spike_mib * 1024.0 * 1024.0;
    ntrack::ThreatDetector threats(tcfg);

    const auto started = std::chrono::steady_clock::now();

    // Prime counters, then wait one interval so the first render has rates.
    try {
        speeds.update();
    } catch (const std::exception& ex) {
        std::cerr << "Failed to read interface stats: " << ex.what() << "\n";
        return 1;
    }
    std::this_thread::sleep_for(
        std::chrono::duration<double>(opt.interval_sec));

    while (g_running) {
        std::vector<ntrack::SpeedSnapshot> ifaces;
        try {
            ifaces = speeds.update();
        } catch (const std::exception& ex) {
            std::cerr << "Interface sample failed: " << ex.what() << "\n";
            break;
        }

        ntrack::ActivitySummary act;
        try {
            act = activity.snapshot();
        } catch (const std::exception& ex) {
            std::cerr << "Activity sample failed: " << ex.what() << "\n";
        }

        auto events = threats.evaluate(speeds.totals(), act);
        const auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - started);

        render(opt, color_on, ifaces, speeds.totals(), act, events, uptime);

        if (opt.once) break;

        std::this_thread::sleep_for(
            std::chrono::duration<double>(opt.interval_sec));
    }

    if (color_on && !opt.once) {
        std::cout << ntrack::term::show_cursor;
    }
    return 0;
}
