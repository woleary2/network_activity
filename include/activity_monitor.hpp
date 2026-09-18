#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ntrack {

enum class Proto { Tcp, Udp };

struct Connection {
    Proto proto = Proto::Tcp;
    std::string local_addr;
    uint16_t local_port = 0;
    std::string remote_addr;
    uint16_t remote_port = 0;
    std::string state;       // ESTABLISHED, LISTEN, etc.
    std::string process;     // best-effort process name
    int pid = -1;
};

struct ActivitySummary {
    std::vector<Connection> connections;
    size_t established = 0;
    size_t listening = 0;
    size_t tcp_total = 0;
    size_t udp_total = 0;
    size_t unique_remotes = 0;
};

class ActivityMonitor {
public:
    ActivitySummary snapshot();

private:
    static std::vector<Connection> list_tcp();
    static std::vector<Connection> list_udp();
    static std::string resolve_process(int pid);
};

}  // namespace ntrack
