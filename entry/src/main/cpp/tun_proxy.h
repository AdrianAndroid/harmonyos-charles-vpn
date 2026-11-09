#pragma once

#include <atomic>
#include <poll.h>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#ifdef __OHOS__
#include <hilog/log.h>
#define CHARLES_LOG_DOMAIN 0xC0DE
#define LOGI(...) OH_LOG_Print(LOG_APP, LOG_INFO, CHARLES_LOG_DOMAIN, "charles_vpn", __VA_ARGS__)
#define LOGW(...) OH_LOG_Print(LOG_APP, LOG_WARN, CHARLES_LOG_DOMAIN, "charles_vpn", __VA_ARGS__)
#define LOGE(...) OH_LOG_Print(LOG_APP, LOG_ERROR, CHARLES_LOG_DOMAIN, "charles_vpn", __VA_ARGS__)
#else
// Host test builds: logging collapses to no-ops so the engine stays single-source.
#define LOGI(...) ((void)0)
#define LOGW(...) ((void)0)
#define LOGE(...) ((void)0)
#endif

namespace charles {

// ---------------------------------------------------------------------------
// Engine scope and known limitations (documented honestly, not hidden):
//  * IPv4 only. IPv6 packets are dropped; there is no IPv6 stack.
//  * Cleartext HTTP/1.x only. TLS/HTTPS is never terminated: CONNECT is
//    rejected with an RST and a TLS ClientHello is detected and RSTed. There is
//    no MITM, no cert handling and no SSL logic.
//  * A fixed 1 s RTO with capped exponential backoff is used rather than full
//    RTT estimation (SRTT/rttvar) and Karn's algorithm. Adequate for a local
//    phone-to-proxy path but not a general-purpose congestion controller.
//  * No TCP options beyond our own MSS option (no SACK, timestamps, window
//    scaling or PAWS). The receive window therefore maxes out at 65535.
//  * Fragment reassembly refuses overlapping fragments outright and enforces
//    bounds/timeouts; it does not implement the historical BSD/Linux overlap
//    policies because this proxy never forwards overlapping fragments.
//  * UDP is limited to a DNS (port 53) request/response relay for hostname
//    resolution. All other UDP, including QUIC/HTTP3, is dropped rather than
//    "passed through" — there is no physical bypass. Browsers fall back to TCP.
//  * Out-of-order TCP data is buffered up to OOO_CAP per flow; beyond that the
//    segment is dropped and retransmission is relied upon (dup ACKs are sent).
// ---------------------------------------------------------------------------

constexpr int MAX_FLOWS = 256;            // hard cap on concurrent TCP flows
constexpr uint16_t ADVERTISED_MSS = 1200; // MSS announced in our SYNACK
// No window scaling is negotiated, so the advertised window is the 16-bit max.
constexpr uint32_t TCP_RCV_WINDOW = 65535u;
constexpr size_t FLOW_APP_CAP = 256u * 1024u;   // client->proxy buffered HTTP bytes
constexpr size_t FLOW_TX_CAP = 1024u * 1024u;   // proxy->client buffered response bytes
constexpr size_t OOO_CAP = 64u * 1024u;         // out-of-order TCP queue per flow
constexpr size_t REASM_CAP = 64u * 1024u;       // one IP datagram reassembly budget
constexpr int RTO_MS = 1000;
constexpr int MAX_RETRANS = 8;
constexpr int CONNECT_TIMEOUT_MS = 10000;
constexpr int IDLE_TIMEOUT_MS = 600000;
constexpr int REASM_TIMEOUT_MS = 30000;
constexpr int DNS_TIMEOUT_MS = 10000;

#pragma pack(push, 1)
struct Ipv4Header {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
};
struct TcpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint16_t data_offset_flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
};
struct UdpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};
#pragma pack(pop)

constexpr uint8_t IPPROTO_TCP_V = 6;
constexpr uint8_t IPPROTO_UDP_V = 17;

struct FlowKey {
    uint32_t client_addr;  // network order
    uint16_t client_port;  // host order
    uint16_t dst_port;     // host order (original destination)
    uint32_t dst_addr;     // network order

    bool operator==(const FlowKey& o) const {
        return client_addr == o.client_addr && client_port == o.client_port &&
               dst_port == o.dst_port && dst_addr == o.dst_addr;
    }
};
struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const {
        uint64_t a = static_cast<uint64_t>(k.client_addr) << 16 | k.client_port;
        uint64_t b = static_cast<uint64_t>(k.dst_addr) << 16 | k.dst_port;
        return std::hash<uint64_t>{}(a ^ (b * 0x9e3779b97f4a7c15ULL));
    }
};

// RFC 1071 ones-complement sum over an arbitrary byte buffer (even/odd length).
uint16_t ones_complement_checksum(const uint8_t* data, size_t len);
// Full transport checksum with the IPv4 pseudo-header (protocol 6/17).
uint16_t transport_checksum_v4(uint32_t src, uint32_t dst, uint8_t protocol,
                               const uint8_t* seg, size_t seg_len);
uint16_t ip_checksum(const Ipv4Header* ip);
// Verify the IPv4 header checksum of a received packet.
bool verify_ip_checksum(const uint8_t* packet, size_t len);

enum class TcpSegClass { duplicate, in_order, out_of_order, beyond_window };

// Pure sequence-number arithmetic used by the receive path and covered by host
// tests. rcv_nxt/seg_seq are absolute sequence numbers; window is bytes.
TcpSegClass classify_tcp_segment(uint32_t rcv_nxt, uint32_t seg_seq, uint32_t seg_len,
                                 uint32_t window, size_t& accept_offset, size_t& accept_len);

// One fragmented IPv4 datagram being rebuilt. All offsets are byte offsets into
// the final datagram payload.
struct Fragment {
    uint16_t offset;
    bool more_fragments;
    std::string data;
};
struct ReassemblyEntry {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t protocol;
    std::map<uint16_t, std::string> segments;  // offset -> payload
    bool have_last = false;
    uint16_t total_length = 0;                 // known once the last fragment arrives
    int64_t last_seen_ms = 0;
};

class FragmentReassembler {
public:
    // Add one fragment (transport payload already extracted). Returns true and
    // fills out when the datagram is complete; false means keep waiting or the
    // fragment was rejected (oversized/overlapping/inconsistent).
    bool add_fragment(uint32_t src, uint32_t dst, uint8_t proto, uint16_t id, uint16_t byte_offset,
                      bool more, const uint8_t* payload, size_t payload_len, int64_t now_ms,
                      std::string& out, std::string& reason);
    void sweep(int64_t now_ms);
    size_t size() const { return entries_.size(); }
    void clear() { entries_.clear(); }

private:
    // Key: src|dst|proto|id
    std::unordered_map<uint64_t, ReassemblyEntry> entries_;
};

// Userspace IPv4/TCP TUN endpoint. One instance owns one worker thread, the
// duplicated TUN fd, the wakeup pipe and every outbound Charles socket.
class TunProxy {
public:
    using EventCallback = std::function<void(const std::string&)>;

    // Defined in the .cpp so unique_ptr<incomplete Flow/DnsEntry> is complete
    // at the point the implicit special members are instantiated.
    TunProxy();
    ~TunProxy();

    TunProxy(const TunProxy&) = delete;
    TunProxy& operator=(const TunProxy&) = delete;

    // Configure the Charles target. Does not touch any fd and never starts the
    // worker; validates the IPv4 literal and port.
    bool configure(const std::string& target_ip, uint16_t target_port, std::string& error);

    // Duplicate fd (the caller keeps the original), go nonblocking and start the
    // poll loop on a worker thread. Fails synchronously with `error` set.
    bool attach(int tun_fd, std::string& error);

    // Idempotent: wakes poll, joins the worker and closes every owned fd.
    void stop();

    bool is_running() const { return running_.load(); }

    // Worker-thread errors are delivered here, never via a raw native call into
    // JS. The NAPI layer installs a TSFN-backed callback.
    void set_event_callback(EventCallback cb);

    static int64_t monotonic_ms();

private:
    struct DnsEntry;
    class Flow;

    void worker_loop();
    void handle_packet(const uint8_t* packet, size_t len, int64_t now_ms);
    void dispatch_transport_(const Ipv4Header* ip, const uint8_t* transport, size_t tlen,
                             int64_t now_ms);
    void handle_tcp(const Ipv4Header* ip, const uint8_t* transport, size_t transport_len,
                    int64_t now_ms);
    void handle_udp(const Ipv4Header* ip, const uint8_t* transport, size_t transport_len,
                    int64_t now_ms);
    void handle_dns_response_(uint64_t key, short revents);
    void send_rst(const Ipv4Header* ip, const TcpHeader* th, size_t seg_len);
    void send_tcp(const FlowKey& k, uint32_t seq, uint32_t ack, uint8_t flags,
                  const uint8_t* data, size_t dlen, uint16_t window, const uint8_t* opts,
                  size_t opts_len);
    void rebuild_pollfds(std::vector<pollfd>& fds);
    void report_event(const std::string& message);
    void emit_packet(const void* data, size_t len);

    std::atomic<bool> running_{false};
    std::thread worker_;
    int tun_fd_ = -1;
    int wake_r_ = -1;
    int wake_w_ = -1;

    std::string proxy_ip_text_;
    uint32_t proxy_addr_ = 0;  // network order
    uint16_t proxy_port_ = 0;

    std::mutex cb_mutex_;
    std::mutex start_mutex_;
    EventCallback event_cb_;

    // unique_ptr keeps the nested Flow/DnsEntry definitions private to the .cpp
    // while still satisfying the container's completeness requirements.
    std::unordered_map<FlowKey, std::unique_ptr<Flow>, FlowKeyHash> flows_;
    FragmentReassembler reassembler_;
    std::unordered_map<uint64_t, std::unique_ptr<DnsEntry>> dns_;
    uint16_t ip_id_ = 0x1000;
};

}  // namespace charles
