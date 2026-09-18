#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace ntrack {

std::string format_bytes(uint64_t bytes);
std::string format_rate(double bytes_per_sec);
std::string format_duration(std::chrono::seconds secs);

// ANSI terminal helpers
namespace term {
constexpr const char* reset   = "\033[0m";
constexpr const char* bold    = "\033[1m";
constexpr const char* dim     = "\033[2m";
constexpr const char* red     = "\033[31m";
constexpr const char* green   = "\033[32m";
constexpr const char* yellow  = "\033[33m";
constexpr const char* blue    = "\033[34m";
constexpr const char* magenta = "\033[35m";
constexpr const char* cyan    = "\033[36m";
constexpr const char* white   = "\033[37m";
constexpr const char* clear   = "\033[2J\033[H";
constexpr const char* hide_cursor = "\033[?25l";
constexpr const char* show_cursor = "\033[?25h";

bool is_tty();
std::string color(const char* code, const std::string& text);
}  // namespace term

struct Sample {
    uint64_t rx_bytes = 0;
    uint64_t tx_bytes = 0;
    uint64_t rx_packets = 0;
    uint64_t tx_packets = 0;
    std::chrono::steady_clock::time_point timestamp;
};

}  // namespace ntrack
