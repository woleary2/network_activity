#include "speed_tracker.hpp"

#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace ntrack {
namespace {

bool is_interesting(const std::string& name) {
    if (name.empty() || name == "lo0" || name.rfind("lo", 0) == 0) return false;
    // Skip virtual / tunnel interfaces that inflate noise by default.
    static const char* skip_prefixes[] = {
        "awdl", "llw", "utun", "bridge", "gif", "stf", "p2p", "ap", "vmnet",
        "anpi"};
    for (const char* p : skip_prefixes) {
        if (name.rfind(p, 0) == 0) return false;
    }
    return true;
}

}  // namespace

std::vector<InterfaceStats> SpeedTracker::collect_interfaces() {
    int mib[6] = {CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST2, 0};
    size_t len = 0;
    if (sysctl(mib, 6, nullptr, &len, nullptr, 0) < 0) {
        throw std::runtime_error("sysctl(NET_RT_IFLIST2) size query failed");
    }

    std::vector<char> buf(len);
    if (sysctl(mib, 6, buf.data(), &len, nullptr, 0) < 0) {
        throw std::runtime_error("sysctl(NET_RT_IFLIST2) read failed");
    }

    std::vector<InterfaceStats> result;
    char* next = buf.data();
    char* end = buf.data() + len;

    while (next < end) {
        auto* ifm = reinterpret_cast<if_msghdr*>(next);
        if (ifm->ifm_msglen == 0) break;
        if (ifm->ifm_type == RTM_IFINFO2) {
            auto* if2 = reinterpret_cast<if_msghdr2*>(next);
            auto* sdl = reinterpret_cast<sockaddr_dl*>(if2 + 1);

            std::string name;
            if (sdl->sdl_nlen > 0) {
                name.assign(sdl->sdl_data, sdl->sdl_nlen);
            } else {
                char tmp[IF_NAMESIZE] = {};
                if_indextoname(if2->ifm_index, tmp);
                name = tmp;
            }

            if (is_interesting(name)) {
                InterfaceStats st;
                st.name = name;
                st.rx_bytes = if2->ifm_data.ifi_ibytes;
                st.tx_bytes = if2->ifm_data.ifi_obytes;
                st.rx_packets = if2->ifm_data.ifi_ipackets;
                st.tx_packets = if2->ifm_data.ifi_opackets;
                st.is_up = (if2->ifm_flags & IFF_UP) != 0;
                // Skip never-used virtual/bridge ports.
                if (st.rx_bytes == 0 && st.tx_bytes == 0) {
                    next += ifm->ifm_msglen;
                    continue;
                }
                result.push_back(st);
            }
        }
        next += ifm->ifm_msglen;
    }
    return result;
}

std::vector<SpeedSnapshot> SpeedTracker::update() {
    const auto now = std::chrono::steady_clock::now();
    auto interfaces = collect_interfaces();
    std::vector<SpeedSnapshot> snaps;

    totals_ = SpeedSnapshot{};
    totals_.interface = "TOTAL";

    for (const auto& iface : interfaces) {
        SpeedSnapshot snap;
        snap.interface = iface.name;
        snap.total_rx = iface.rx_bytes;
        snap.total_tx = iface.tx_bytes;
        snap.is_up = iface.is_up;

        auto it = previous_.find(iface.name);
        if (it != previous_.end()) {
            const double dt =
                std::chrono::duration<double>(now - it->second.timestamp).count();
            if (dt > 0.0) {
                const auto drx = iface.rx_bytes >= it->second.rx_bytes
                                     ? iface.rx_bytes - it->second.rx_bytes
                                     : 0;
                const auto dtx = iface.tx_bytes >= it->second.tx_bytes
                                     ? iface.tx_bytes - it->second.tx_bytes
                                     : 0;
                snap.download_bps = static_cast<double>(drx) / dt;
                snap.upload_bps = static_cast<double>(dtx) / dt;
            }
        }

        Sample sample;
        sample.rx_bytes = iface.rx_bytes;
        sample.tx_bytes = iface.tx_bytes;
        sample.rx_packets = iface.rx_packets;
        sample.tx_packets = iface.tx_packets;
        sample.timestamp = now;
        previous_[iface.name] = sample;

        totals_.download_bps += snap.download_bps;
        totals_.upload_bps += snap.upload_bps;
        totals_.total_rx += snap.total_rx;
        totals_.total_tx += snap.total_tx;
        if (snap.is_up) totals_.is_up = true;

        snaps.push_back(snap);
    }

    return snaps;
}

}  // namespace ntrack
