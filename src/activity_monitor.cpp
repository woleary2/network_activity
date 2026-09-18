#include "activity_monitor.hpp"

#include <array>
#include <algorithm>
#include <cstdio>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace ntrack {
namespace {

std::string run_cmd(const char* cmd) {
    std::string out;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) return out;
    std::array<char, 512> buf{};
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe.get())) {
        out += buf.data();
    }
    return out;
}

// Split "host:port" or "[ipv6]:port" or "*:port"
bool parse_endpoint(const std::string& ep, std::string& addr, uint16_t& port) {
    if (ep == "*.*" || ep == "*:*") {
        addr = "*";
        port = 0;
        return true;
    }
    if (!ep.empty() && ep.front() == '[') {
        auto close = ep.find(']');
        if (close == std::string::npos) return false;
        addr = ep.substr(1, close - 1);
        if (close + 1 >= ep.size() || ep[close + 1] != ':') return false;
        port = static_cast<uint16_t>(std::stoul(ep.substr(close + 2)));
        return true;
    }
    auto pos = ep.rfind(':');
    if (pos == std::string::npos) return false;
    addr = ep.substr(0, pos);
    if (addr == "*") {
        port = (ep.substr(pos + 1) == "*")
                   ? 0
                   : static_cast<uint16_t>(std::stoul(ep.substr(pos + 1)));
        return true;
    }
    try {
        port = static_cast<uint16_t>(std::stoul(ep.substr(pos + 1)));
    } catch (...) {
        return false;
    }
    return true;
}

// lsof NAME field: "192.168.1.1:443->8.8.8.8:53" or "*:8080" or "[fe80::1]:80->[fe80::2]:443"
bool parse_lsof_name(const std::string& name, std::string& local_addr,
                     uint16_t& local_port, std::string& remote_addr,
                     uint16_t& remote_port) {
    auto arrow = name.find("->");
    std::string left = (arrow == std::string::npos) ? name : name.substr(0, arrow);
    std::string right =
        (arrow == std::string::npos) ? "" : name.substr(arrow + 2);
    if (!parse_endpoint(left, local_addr, local_port)) return false;
    if (right.empty()) {
        remote_addr = "*";
        remote_port = 0;
        return true;
    }
    return parse_endpoint(right, remote_addr, remote_port);
}

std::string extract_state(const std::string& name) {
    auto open = name.rfind('(');
    auto close = name.rfind(')');
    if (open != std::string::npos && close != std::string::npos &&
        close > open) {
        return name.substr(open + 1, close - open - 1);
    }
    return "";
}

std::vector<Connection> parse_lsof(const std::string& text, Proto proto) {
    std::vector<Connection> out;
    std::istringstream iss(text);
    std::string line;
    // Skip header
    std::getline(iss, line);

    // COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
    // NAME may contain spaces inside IPv6 brackets; take from column 9 onward.
    while (std::getline(iss, line)) {
        if (line.empty()) continue;
        std::istringstream ls(line);
        std::string command, pid_s, user, fd, type, device, sizeoff, node;
        if (!(ls >> command >> pid_s >> user >> fd >> type >> device >> sizeoff >>
              node)) {
            continue;
        }
        std::string name;
        std::getline(ls, name);
        // trim leading space
        while (!name.empty() && name.front() == ' ') name.erase(name.begin());
        if (name.empty()) continue;

        std::string state = extract_state(name);
        std::string name_core = name;
        auto paren = name_core.rfind(" (");
        if (paren != std::string::npos) name_core = name_core.substr(0, paren);

        Connection c;
        c.proto = proto;
        c.process = command;
        try {
            c.pid = std::stoi(pid_s);
        } catch (...) {
            c.pid = -1;
        }
        if (!parse_lsof_name(name_core, c.local_addr, c.local_port,
                             c.remote_addr, c.remote_port)) {
            continue;
        }
        if (proto == Proto::Tcp) {
            c.state = state.empty() ? "UNKNOWN" : state;
        } else {
            c.state = (c.remote_port == 0) ? "UNCONN" : "CONN";
        }
        out.push_back(std::move(c));
    }
    return out;
}

// Fallback when lsof is unavailable: netstat without process names.
std::vector<Connection> parse_netstat(const std::string& text, Proto proto) {
    std::vector<Connection> out;
    std::istringstream iss(text);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.rfind("tcp", 0) != 0 && line.rfind("udp", 0) != 0) continue;
        std::istringstream ls(line);
        std::string p, rq, sq, local, foreign, state;
        if (!(ls >> p >> rq >> sq >> local >> foreign)) continue;
        if (proto == Proto::Tcp) ls >> state;

        // netstat uses dot before port: 192.168.1.10.443 or *.22
        auto split_dot_port = [](std::string ep, std::string& addr,
                                 uint16_t& port) {
            if (!ep.empty() && ep.front() == '*') {
                // *.443 or *.*
                auto dot = ep.rfind('.');
                addr = "*";
                if (dot == std::string::npos || ep.substr(dot + 1) == "*") {
                    port = 0;
                } else {
                    port = static_cast<uint16_t>(std::stoul(ep.substr(dot + 1)));
                }
                return true;
            }
            auto dot = ep.rfind('.');
            if (dot == std::string::npos) return false;
            addr = ep.substr(0, dot);
            try {
                port = static_cast<uint16_t>(std::stoul(ep.substr(dot + 1)));
            } catch (...) {
                return false;
            }
            return true;
        };

        Connection c;
        c.proto = proto;
        c.process = "?";
        c.pid = -1;
        if (!split_dot_port(local, c.local_addr, c.local_port)) continue;
        if (!split_dot_port(foreign, c.remote_addr, c.remote_port)) continue;
        if (proto == Proto::Tcp) {
            c.state = state.empty() ? "UNKNOWN" : state;
        } else {
            c.state = (c.remote_port == 0) ? "UNCONN" : "CONN";
        }
        out.push_back(std::move(c));
    }
    return out;
}

}  // namespace

std::string ActivityMonitor::resolve_process(int /*pid*/) { return "?"; }

std::vector<Connection> ActivityMonitor::list_tcp() {
    // ESTABLISHED + LISTEN cover the interesting activity surface.
    auto text = run_cmd("lsof -nP -iTCP -sTCP:ESTABLISHED,LISTEN 2>/dev/null");
    if (!text.empty() && text.find("COMMAND") != std::string::npos) {
        return parse_lsof(text, Proto::Tcp);
    }
    text = run_cmd("netstat -an -p tcp 2>/dev/null");
    return parse_netstat(text, Proto::Tcp);
}

std::vector<Connection> ActivityMonitor::list_udp() {
    auto text = run_cmd("lsof -nP -iUDP 2>/dev/null");
    if (!text.empty() && text.find("COMMAND") != std::string::npos) {
        auto all = parse_lsof(text, Proto::Udp);
        // UDP listen table is huge; keep connected or named local ports.
        std::vector<Connection> filtered;
        for (auto& c : all) {
            if (c.remote_port != 0 || c.local_port != 0) {
                filtered.push_back(std::move(c));
            }
        }
        if (filtered.size() > 40) filtered.resize(40);
        return filtered;
    }
    text = run_cmd("netstat -an -p udp 2>/dev/null");
    auto all = parse_netstat(text, Proto::Udp);
    if (all.size() > 40) all.resize(40);
    return all;
}

ActivitySummary ActivityMonitor::snapshot() {
    ActivitySummary summary;
    auto tcp = list_tcp();
    auto udp = list_udp();

    summary.tcp_total = tcp.size();
    summary.udp_total = udp.size();
    summary.connections.reserve(tcp.size() + udp.size());

    std::set<std::string> remotes;
    for (auto& c : tcp) {
        if (c.state == "ESTABLISHED") ++summary.established;
        if (c.state == "LISTEN") ++summary.listening;
        if (!c.remote_addr.empty() && c.remote_addr != "*" &&
            c.remote_addr != "0.0.0.0" && c.remote_addr != "::" &&
            c.remote_port != 0) {
            remotes.insert(c.remote_addr);
        }
        summary.connections.push_back(std::move(c));
    }
    for (auto& c : udp) {
        if (!c.remote_addr.empty() && c.remote_addr != "*" &&
            c.remote_addr != "0.0.0.0" && c.remote_addr != "::" &&
            c.remote_port != 0) {
            remotes.insert(c.remote_addr);
        }
        summary.connections.push_back(std::move(c));
    }
    summary.unique_remotes = remotes.size();

    std::sort(summary.connections.begin(), summary.connections.end(),
              [](const Connection& a, const Connection& b) {
                  if (a.state == "ESTABLISHED" && b.state != "ESTABLISHED")
                      return true;
                  if (b.state == "ESTABLISHED" && a.state != "ESTABLISHED")
                      return false;
                  if (a.state == "LISTEN" && b.state != "LISTEN") return true;
                  if (b.state == "LISTEN" && a.state != "LISTEN") return false;
                  return a.remote_port > b.remote_port;
              });

    return summary;
}

}  // namespace ntrack
