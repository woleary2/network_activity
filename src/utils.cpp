#include "utils.hpp"

#include <cstdio>
#include <iomanip>
#include <sstream>
#include <unistd.h>

namespace ntrack {

std::string format_bytes(uint64_t bytes) {
    const char* units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double value = static_cast<double>(bytes);
    int unit = 0;
    while (value >= 1024.0 && unit < 4) {
        value /= 1024.0;
        ++unit;
    }
    std::ostringstream oss;
    if (unit == 0) {
        oss << bytes << " " << units[unit];
    } else {
        oss << std::fixed << std::setprecision(value >= 10.0 ? 1 : 2) << value
            << " " << units[unit];
    }
    return oss.str();
}

std::string format_rate(double bytes_per_sec) {
    if (bytes_per_sec < 0) bytes_per_sec = 0;
    const char* units[] = {"B/s", "KiB/s", "MiB/s", "GiB/s"};
    double value = bytes_per_sec;
    int unit = 0;
    while (value >= 1024.0 && unit < 3) {
        value /= 1024.0;
        ++unit;
    }
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(value >= 10.0 ? 1 : 2) << value
        << " " << units[unit];
    return oss.str();
}

std::string format_duration(std::chrono::seconds secs) {
    auto s = secs.count();
    if (s < 0) s = 0;
    const auto h = s / 3600;
    const auto m = (s % 3600) / 60;
    const auto sec = s % 60;
    std::ostringstream oss;
    if (h > 0) {
        oss << h << "h " << m << "m";
    } else if (m > 0) {
        oss << m << "m " << sec << "s";
    } else {
        oss << sec << "s";
    }
    return oss.str();
}

namespace term {

bool is_tty() {
    return isatty(STDOUT_FILENO) != 0;
}

std::string color(const char* code, const std::string& text) {
    if (!is_tty()) return text;
    return std::string(code) + text + reset;
}

}  // namespace term

}  // namespace ntrack
