#include "tun_proxy.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <ctime>
#include <exception>

#include "http_request.h"

namespace charles {
namespace {

constexpr uint8_t TH_FIN = 0x01;
constexpr uint8_t TH_SYN = 0x02;
constexpr uint8_t TH_RST = 0x04;
constexpr uint8_t TH_PSH = 0x08;
constexpr uint8_t TH_ACK = 0x10;

constexpr uint16_t IP_DF = 0x4000;
constexpr uint16_t IP_MF = 0x2000;
constexpr uint16_t IP_OFFMASK = 0x1fff;

int64_t now_ms() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<int64_t>(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;
}

bool set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return false;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

uint32_t wrap_add(uint32_t a, uint32_t b) { return static_cast<uint32_t>(a + b); }

// Base64 is used only for UI trace payloads. Trace messages are tab-delimited,
// so HTTP headers/bodies must not inject separators or newlines.
std::string base64_encode(const std::string& input) {
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((input.size() + 2) / 3 * 4);
    size_t i = 0;
    while (i + 3 <= input.size()) {
        uint32_t n = (static_cast<uint8_t>(input[i]) << 16) |
                     (static_cast<uint8_t>(input[i + 1]) << 8) |
                     static_cast<uint8_t>(input[i + 2]);
        out.push_back(table[(n >> 18) & 0x3f]);
        out.push_back(table[(n >> 12) & 0x3f]);
        out.push_back(table[(n >> 6) & 0x3f]);
        out.push_back(table[n & 0x3f]);
        i += 3;
    }
    if (i < input.size()) {
        bool two_bytes = i + 1 < input.size();
        uint32_t n = static_cast<uint8_t>(input[i]) << 16;
        if (two_bytes) n |= static_cast<uint8_t>(input[i + 1]) << 8;
        out.push_back(table[(n >> 18) & 0x3f]);
        out.push_back(table[(n >> 12) & 0x3f]);
        if (two_bytes) {
            out.push_back(table[(n >> 6) & 0x3f]);
            out.push_back('=');
        } else {
            out.push_back('=');
            out.push_back('=');
        }
    }
    return out;
}

std::string preview_b64(const std::string& text, size_t limit) {
    return base64_encode(text.substr(0, std::min(text.size(), limit)));
}

std::string ascii_lower_copy(const std::string& text) {
    std::string out = text;
    for (char& c : out) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

std::string trim_spaces(const std::string& text) {
    size_t begin = 0;
    while (begin < text.size() && (text[begin] == ' ' || text[begin] == '\t')) ++begin;
    size_t end = text.size();
    while (end > begin && (text[end - 1] == ' ' || text[end - 1] == '\t')) --end;
    return text.substr(begin, end - begin);
}

}  // namespace

// ---------------------------------------------------------------------------
// Checksums (RFC 1071) and pure TCP sequence arithmetic — host-testable.
// ---------------------------------------------------------------------------

uint16_t ones_complement_checksum(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    size_t i = 0;
    for (; i + 1 < len; i += 2) {
        sum += static_cast<uint32_t>(data[i]) << 8 | data[i + 1];
    }
    if (i < len) sum += static_cast<uint32_t>(data[i]) << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

uint16_t transport_checksum_v4(uint32_t src, uint32_t dst, uint8_t protocol,
                               const uint8_t* seg, size_t seg_len) {
    uint32_t sum = 0;
    // Pseudo-header. The addresses are stored in network byte order, so read
    // their 16-bit words directly off the byte representation. Mixing host-order
    // pseudo words with network-order segment words would corrupt the sum.
    const auto* sb = reinterpret_cast<const uint8_t*>(&src);
    const auto* db = reinterpret_cast<const uint8_t*>(&dst);
    sum += static_cast<uint16_t>((sb[0] << 8) | sb[1]);
    sum += static_cast<uint16_t>((sb[2] << 8) | sb[3]);
    sum += static_cast<uint16_t>((db[0] << 8) | db[1]);
    sum += static_cast<uint16_t>((db[2] << 8) | db[3]);
    sum += protocol;
    sum += static_cast<uint16_t>(seg_len);  // big-endian word value == host value
    size_t i = 0;
    for (; i + 1 < seg_len; i += 2) {
        sum += static_cast<uint32_t>(seg[i]) << 8 | seg[i + 1];
    }
    if (i < seg_len) sum += static_cast<uint32_t>(seg[i]) << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

uint16_t ip_checksum(const Ipv4Header* ip) {
    size_t hlen = static_cast<size_t>(ip->version_ihl & 0x0f) * 4;
    return ones_complement_checksum(reinterpret_cast<const uint8_t*>(ip), hlen);
}

bool verify_ip_checksum(const uint8_t* packet, size_t len) {
    if (len < sizeof(Ipv4Header)) return false;
    const auto* ip = reinterpret_cast<const Ipv4Header*>(packet);
    size_t hlen = static_cast<size_t>(ip->version_ihl & 0x0f) * 4;
    if (hlen < 20 || hlen > len) return false;
    return ones_complement_checksum(packet, hlen) == 0;
}

TcpSegClass classify_tcp_segment(uint32_t rcv_nxt, uint32_t seg_seq, uint32_t seg_len,
                                 uint32_t window, size_t& accept_offset, size_t& accept_len) {
    accept_offset = 0;
    accept_len = 0;
    if (seg_len == 0) {
        return seg_seq == rcv_nxt ? TcpSegClass::duplicate : TcpSegClass::beyond_window;
    }
    int32_t diff = static_cast<int32_t>(seg_seq - rcv_nxt);
    if (diff == 0) {
        accept_len = std::min<uint32_t>(seg_len, window);
        return accept_len == 0 ? TcpSegClass::beyond_window : TcpSegClass::in_order;
    }
    if (diff < 0) {
        // Retransmitted segment overlapping the already-received boundary.
        uint32_t skip = static_cast<uint32_t>(-diff);
        if (skip >= seg_len) return TcpSegClass::duplicate;
        accept_offset = skip;
        uint32_t room = window > static_cast<uint32_t>(-diff)
                            ? window - static_cast<uint32_t>(-diff)
                            : 0;
        accept_len = std::min<uint32_t>(seg_len - skip, room);
        return accept_len == 0 ? TcpSegClass::duplicate : TcpSegClass::in_order;
    }
    // diff > 0: genuine gap.
    if (static_cast<uint32_t>(diff) >= window) return TcpSegClass::beyond_window;
    accept_len = std::min<uint32_t>(seg_len, window - static_cast<uint32_t>(diff));
    return TcpSegClass::out_of_order;
}

// ---------------------------------------------------------------------------
// IPv4 fragment reassembly
// ---------------------------------------------------------------------------

bool FragmentReassembler::add_fragment(uint32_t src, uint32_t dst, uint8_t proto, uint16_t id,
                                       uint16_t byte_offset, bool more, const uint8_t* payload,
                                       size_t payload_len, int64_t now_ms, std::string& out,
                                       std::string& reason) {
    if (byte_offset % 8 != 0) {
        reason = "fragment offset not 8-byte aligned";
        return false;
    }
    if (payload_len == 0 && more) {
        reason = "empty non-final fragment";
        return false;
    }
    // FNV-1a mix so swapped src/dst or differing proto/id cannot alias keys.
    uint64_t key = 1469598103934665603ULL;
    auto mix = [&key](uint64_t v) {
        key ^= v;
        key *= 1099511628211ULL;
    };
    mix(src);
    mix(dst);
    mix(proto);
    mix(id);
    ReassemblyEntry& e = entries_[key];
    if (e.segments.empty()) {
        e.src_addr = src;
        e.dst_addr = dst;
        e.protocol = proto;
    } else if (e.src_addr != src || e.dst_addr != dst || e.protocol != proto) {
        reason = "reassembly key collision";
        entries_.erase(key);
        return false;
    }
    e.last_seen_ms = now_ms;

    if (static_cast<size_t>(byte_offset) + payload_len > REASM_CAP) {
        reason = "reassembled datagram exceeds cap";
        entries_.erase(key);
        return false;
    }
    // Refuse overlaps rather than guessing which copy wins.
    size_t begin = byte_offset;
    size_t finish = begin + payload_len;
    for (const auto& kv : e.segments) {
        size_t o = kv.first;
        size_t l = kv.second.size();
        if (begin < o + l && o < finish) {
            reason = "overlapping fragments";
            entries_.erase(key);
            return false;
        }
    }
    e.segments[byte_offset] = std::string(reinterpret_cast<const char*>(payload), payload_len);
    if (!more) {
        e.have_last = true;
        e.total_length = static_cast<uint16_t>(byte_offset + payload_len);
    }
    if (!e.have_last) return false;

    // Walk the sorted segments and require gap-free coverage of the full length.
    uint16_t cursor = 0;
    for (const auto& kv : e.segments) {
        if (kv.first != cursor) return false;  // gap still open
        cursor = static_cast<uint16_t>(cursor + kv.second.size());
        if (cursor > e.total_length) {
            reason = "fragment overshoots declared length";
            entries_.erase(key);
            return false;
        }
    }
    if (cursor != e.total_length) return false;

    out.clear();
    out.reserve(e.total_length);
    for (auto& kv : e.segments) out += kv.second;
    entries_.erase(key);
    return true;
}

void FragmentReassembler::sweep(int64_t now) {
    for (auto it = entries_.begin(); it != entries_.end();) {
        if (now - it->second.last_seen_ms > REASM_TIMEOUT_MS)
            it = entries_.erase(it);
        else
            ++it;
    }
}

// ---------------------------------------------------------------------------
// Per-flow TCP endpoint + HTTP relay
// ---------------------------------------------------------------------------

struct TunProxy::DnsEntry {
    int sock = -1;
    uint32_t client_addr = 0;
    uint16_t client_port = 0;
    uint32_t resolver_addr = 0;
    int64_t deadline = 0;
};

class TunProxy::Flow {
public:
    enum class State { SYN_RCVD, CONNECTING, ESTABLISHED, FIN_WAIT, CLOSING, DEAD };

    Flow(TunProxy* owner, const FlowKey& key)
        : owner_(owner), key_(key), id_(owner->next_flow_id()), created_ms_(now_ms()) {
        iss_ = static_cast<uint32_t>(created_ms_ ^ reinterpret_cast<uintptr_t>(this));
    }

    ~Flow() {
        report_close_();
        if (sock_ >= 0) ::close(sock_);
    }

    int sock() const { return sock_; }
    State state() const { return state_; }

    short wanted_events() const {
        if (state_ == State::DEAD || sock_ < 0) return 0;
        short ev = 0;
        if (state_ == State::CONNECTING) ev |= POLLOUT;
        if (connected_) {
            if (!upstream_eof_ && tx_buf_.size() < FLOW_TX_CAP) ev |= POLLIN;
            if (!up_out_.empty() || has_unsent_data_() ||
                (upstream_eof_ && !fin_sent_))
                ev |= POLLOUT;
        }
        return ev;
    }

    // Client SYN: initialize the relay side and answer with a SYNACK.
    void on_syn(const TcpHeader* th, int64_t now) {
        rcv_nxt_ = wrap_add(ntohl(th->seq), 1);
        snd_una_ = iss_;
        snd_nxt_ = wrap_add(iss_, 1);  // SYN consumes one sequence number
        rto_deadline_ = now + RTO_MS;
        retrans_ = 0;
        send_synack_();
        state_ = State::SYN_RCVD;
        last_activity_ = now;
    }

    void on_tcp(const TcpHeader* th, const uint8_t* payload, size_t dlen, int64_t now) {
        if (state_ == State::DEAD) return;  // awaiting erase by the next tick
        last_activity_ = now;
        uint8_t flags = static_cast<uint8_t>(ntohs(th->data_offset_flags) & 0xff);
        uint32_t seg_seq = ntohl(th->seq);
        snd_wnd_ = ntohs(th->window);
        if (snd_wnd_ == 0) snd_wnd_ = 1;  // keep probing; zero windows are rare on phones

        if (flags & TH_RST) {
            die_(false);
            return;
        }

        if (state_ == State::SYN_RCVD) {
            // The ACK that completes the three-way handshake.
            if ((flags & TH_ACK) && ntohl(th->ack) == snd_nxt_) {
                state_ = State::ESTABLISHED;
                // The SYN is now acknowledged; tx_buf_ is indexed from snd_una_,
                // so this must advance before any response byte is sent.
                snd_una_ = snd_nxt_;
                rto_deadline_ = 0;
                open_upstream_(now);
                if (state_ == State::DEAD) return;  // upstream socket failed
            } else if (flags & TH_SYN) {
                send_synack_();  // retransmitted client SYN
                return;
            } else {
                send_ack_();
                return;
            }
        }

        if (flags & TH_SYN) {
            // Spurious/retransmitted SYN after establishment: re-ack and ignore.
            send_ack_();
            return;
        }

        // ACK processing for our outgoing data.
        if (flags & TH_ACK) process_ack_(ntohl(th->ack), now);

        if (dlen > 0) ingest_data_(seg_seq, payload, dlen, now);

        if (flags & TH_FIN) {
            uint32_t fin_seq = wrap_add(seg_seq, static_cast<uint32_t>(dlen));
            if (fin_seq == rcv_nxt_) {
                rcv_nxt_ = wrap_add(rcv_nxt_, 1);
                fin_rcvd_ = true;
                send_ack_();
            } else {
                have_ooo_fin_ = true;
                ooo_fin_ = fin_seq;  // applied by drain_ooo_ once the gap fills
            }
        }

        pump_app_(now);
        if (fin_rcvd_ && app_in_.empty() && up_out_.empty() && !half_closed_) {
            half_closed_ = true;
            if (sock_ >= 0) shutdown(sock_, SHUT_WR);
            if (state_ == State::ESTABLISHED) state_ = State::FIN_WAIT;
        }
        pump_tx_();
    }

    void on_poll(short revents, int64_t now) {
        last_activity_ = now;
        if (revents & (POLLERR | POLLNVAL)) {
            die_(true);
            return;
        }
        if (state_ == State::CONNECTING && (revents & POLLOUT)) {
            int err = 0;
            socklen_t slen = sizeof(err);
            if (getsockopt(sock_, SOL_SOCKET, SO_ERROR, &err, &slen) < 0 || err != 0) {
                owner_->report_event(std::string("Charles连接失败：") +
                                     (err != 0 ? std::strerror(err) : std::strerror(errno)));
                die_(true);
                return;
            }
            connected_ = true;
            state_ = State::ESTABLISHED;
        }
        if (revents & POLLOUT) {
            flush_up_out_();
            pump_tx_();
        }
        if (connected_ && (revents & (POLLIN | POLLHUP))) read_upstream_();
        pump_app_(now);
        pump_tx_();
        if (fin_rcvd_ && app_in_.empty() && up_out_.empty() && !half_closed_) {
            half_closed_ = true;
            if (sock_ >= 0) shutdown(sock_, SHUT_WR);
            if (state_ == State::ESTABLISHED) state_ = State::FIN_WAIT;
        }
    }

    // Returns false when the flow must be destroyed.
    bool tick(int64_t now) {
        if (state_ == State::DEAD) return false;
        if (state_ == State::CONNECTING && now - connect_start_ > CONNECT_TIMEOUT_MS) {
            owner_->report_event("连接Charles超时");
            die_(true);
            return false;
        }
        if (now - last_activity_ > IDLE_TIMEOUT_MS) {
            die_(true);
            return false;
        }
        bool unacked = snd_nxt_ != snd_una_ || (fin_sent_ && !fin_acked_) ||
                       state_ == State::SYN_RCVD;
        // rto_deadline_ == 0 means nothing is currently being timed.
        if (unacked && rto_deadline_ != 0 && now >= rto_deadline_) {
            ++retrans_;
            if (retrans_ > MAX_RETRANS) {
                die_(true);
                return false;
            }
            retransmit_();
            int backoff = std::min(retrans_, 4);
            rto_deadline_ = now + (RTO_MS << backoff);
        }
        // Once our FIN is acknowledged and nothing is in flight, the endpoint
        // can be reaped without waiting for the client's final ACK timeout.
        if (state_ == State::CLOSING && tx_buf_.empty() && fin_acked_ &&
            snd_nxt_ == snd_una_) {
            return false;
        }
        return true;
    }

private:
    TunProxy* owner_;
    FlowKey key_;
    uint64_t id_ = 0;
    int64_t created_ms_ = 0;
    bool close_reported_ = false;
    bool trace_flow_started_ = false;
    uint64_t request_bytes_ = 0;
    uint64_t response_bytes_ = 0;
    std::string last_method_;
    std::string last_host_;
    std::string last_target_;
    int64_t last_request_ms_ = 0;
    int response_index_ = 0;

    std::string resp_parse_buf_;
    bool resp_header_parsed_ = false;
    bool resp_chunked_ = false;
    bool resp_until_close_ = false;
    bool resp_chunk_need_size_ = true;
    bool resp_chunk_need_crlf_ = false;
    bool resp_chunk_trailers_ = false;
    size_t resp_chunk_remaining_ = 0;
    size_t resp_body_remaining_ = 0;
    size_t resp_body_bytes_ = 0;
    size_t resp_content_length_ = 0;
    bool resp_has_content_length_ = false;
    std::string resp_status_line_;
    std::string resp_header_raw_;
    std::string resp_preview_;
    bool resp_preview_emitted_ = false;
    bool resp_parse_disabled_ = false;
    int64_t resp_started_ms_ = 0;
    int current_resp_index_ = 0;

    int sock_ = -1;
    State state_ = State::SYN_RCVD;
    bool connected_ = false;
    bool upstream_eof_ = false;
    bool half_closed_ = false;

    uint32_t iss_ = 0;
    uint32_t rcv_nxt_ = 0;
    uint32_t snd_una_ = 0;
    uint32_t snd_nxt_ = 0;
    uint16_t snd_wnd_ = TCP_RCV_WINDOW;
    bool fin_sent_ = false;
    bool fin_acked_ = false;
    bool fin_rcvd_ = false;
    uint32_t ooo_fin_ = 0;
    bool have_ooo_fin_ = false;

    int retrans_ = 0;
    int64_t rto_deadline_ = 0;
    int64_t last_activity_ = 0;
    int64_t connect_start_ = 0;

    std::string app_in_;  // in-order, unconsumed client application bytes
    std::string up_out_;  // bytes waiting to be written to Charles
    std::string tx_buf_;  // unacked + unsent response bytes, base seq snd_una_
    std::map<uint32_t, std::string> ooo_;
    size_t ooo_bytes_ = 0;
    bool http_checked_ = false;

    enum class BodyPhase { REQUEST_HEADER, CONTENT_LENGTH, CHUNKED } phase_ =
        BodyPhase::REQUEST_HEADER;
    int64_t body_remaining_ = 0;

    bool has_unsent_data_() const {
        return static_cast<uint32_t>(tx_buf_.size()) > (snd_nxt_ - snd_una_);
    }

    uint16_t rcv_window_() const {
        size_t backlog = app_in_.size() + ooo_bytes_;
        if (backlog >= TCP_RCV_WINDOW) return 0;
        return static_cast<uint16_t>(TCP_RCV_WINDOW - backlog);
    }

    void send_segment_(uint8_t flags, const uint8_t* data, size_t dlen, const uint8_t* opts,
                       size_t opts_len) {
        owner_->send_tcp(key_, snd_nxt_, rcv_nxt_, flags, data, dlen, rcv_window_(), opts,
                         opts_len);
    }

    void send_ack_() { send_segment_(TH_ACK, nullptr, 0, nullptr, 0); }

    void send_synack_() {
        static const uint8_t mss_opt[] = {0x02, 0x04,
                                          static_cast<uint8_t>(ADVERTISED_MSS >> 8),
                                          static_cast<uint8_t>(ADVERTISED_MSS & 0xff)};
        snd_nxt_ = wrap_add(iss_, 1);
        owner_->send_tcp(key_, iss_, rcv_nxt_, TH_SYN | TH_ACK, nullptr, 0, rcv_window_(),
                         mss_opt, sizeof(mss_opt));
    }

    void open_upstream_(int64_t now) {
        connect_start_ = now;
        sock_ = socket(AF_INET, SOCK_STREAM, 0);
        if (sock_ < 0) {
            owner_->report_event(std::string("无法创建Charles socket：") + std::strerror(errno));
            die_(true);
            return;
        }
        if (!set_nonblocking(sock_)) {
            die_(true);
            return;
        }
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(owner_->proxy_port_);
        addr.sin_addr.s_addr = owner_->proxy_addr_;
        int rc = connect(sock_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        if (rc == 0) {
            connected_ = true;
            state_ = State::ESTABLISHED;
        } else if (errno == EINPROGRESS) {
            state_ = State::CONNECTING;
        } else {
            owner_->report_event(std::string("Charles连接失败：") + std::strerror(errno));
            die_(true);
        }
    }

    void process_ack_(uint32_t ack, int64_t now) {
        (void)now;
        int32_t rel = static_cast<int32_t>(ack - snd_una_);
        if (rel <= 0 || static_cast<int32_t>(ack - snd_nxt_) > 0) {
            return;  // duplicate ACK or an invalid ACK beyond data we sent
        }
        if (fin_sent_ && !fin_acked_ &&
            static_cast<int32_t>(ack - wrap_add(fin_seq_value_, 1)) >= 0) {
            // A FIN consumes one sequence number but occupies no tx_buf_ byte.
            // Its ACK also acknowledges all preceding response data.
            tx_buf_.clear();
            snd_una_ = snd_nxt_;
            fin_acked_ = true;
        } else {
            size_t consume = std::min<size_t>(static_cast<uint32_t>(rel), tx_buf_.size());
            tx_buf_.erase(0, consume);
            snd_una_ = wrap_add(snd_una_, static_cast<uint32_t>(consume));
        }
        if (snd_nxt_ == snd_una_ && !(fin_sent_ && !fin_acked_)) rto_deadline_ = 0;
        if (fin_acked_ && upstream_eof_ && tx_buf_.empty()) state_ = State::CLOSING;
    }

    void ingest_data_(uint32_t seg_seq, const uint8_t* payload, size_t dlen, int64_t now) {
        (void)now;
        size_t off = 0;
        size_t accept = 0;
        TcpSegClass cls = classify_tcp_segment(rcv_nxt_, seg_seq, static_cast<uint32_t>(dlen),
                                               rcv_window_(), off, accept);
        if (cls == TcpSegClass::beyond_window || cls == TcpSegClass::duplicate) {
            send_ack_();  // dup ACK helps fast retransmit on the client
            return;
        }
        const uint8_t* p = payload + off;
        uint32_t begin = wrap_add(seg_seq, static_cast<uint32_t>(off));
        if (cls == TcpSegClass::in_order) {
            app_in_.append(reinterpret_cast<const char*>(p), accept);
            rcv_nxt_ = wrap_add(rcv_nxt_, static_cast<uint32_t>(accept));
            drain_ooo_();
        } else {
            if (ooo_bytes_ + accept > OOO_CAP) {
                send_ack_();
                return;  // bounded: wait for retransmission rather than grow forever
            }
            if (ooo_.find(begin) == ooo_.end()) {
                ooo_[begin] = std::string(reinterpret_cast<const char*>(p), accept);
                ooo_bytes_ += accept;
            }
        }
        send_ack_();
    }

    void drain_ooo_() {
        bool progress = true;
        while (progress) {
            progress = false;
            auto it = ooo_.find(rcv_nxt_);
            if (it != ooo_.end()) {
                app_in_ += it->second;
                ooo_bytes_ -= it->second.size();
                rcv_nxt_ = wrap_add(rcv_nxt_, static_cast<uint32_t>(it->second.size()));
                ooo_.erase(it);
                progress = true;
            }
            if (have_ooo_fin_ && ooo_fin_ == rcv_nxt_) {
                rcv_nxt_ = wrap_add(rcv_nxt_, 1);
                fin_rcvd_ = true;
                have_ooo_fin_ = false;
                progress = true;
            }
        }
    }

    void read_upstream_() {
        char buf[8192];
        for (;;) {
            ssize_t n = ::read(sock_, buf, sizeof(buf));
            if (n > 0) {
                if (tx_buf_.size() + static_cast<size_t>(n) > FLOW_TX_CAP) {
                    // Should not happen: POLLIN is disabled once the cap is hit.
                    break;
                }
                tx_buf_.append(buf, static_cast<size_t>(n));
                on_upstream_data_(buf, static_cast<size_t>(n));
                continue;
            }
            if (n == 0) {
                upstream_eof_ = true;
                break;
            }
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            owner_->report_event(std::string("读取Charles响应失败：") + std::strerror(errno));
            die_(true);
            return;
        }
    }

    void flush_up_out_() {
        while (!up_out_.empty()) {
            ssize_t n = ::write(sock_, up_out_.data(), up_out_.size());
            if (n > 0) {
                up_out_.erase(0, static_cast<size_t>(n));
                continue;
            }
            if (n < 0 && errno == EINTR) continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            die_(true);
            return;
        }
    }

    void pump_tx_() {
        if (state_ == State::SYN_RCVD || state_ == State::CONNECTING || sock_ < 0) return;
        uint32_t unacked = snd_nxt_ - snd_una_;
        size_t sent = unacked;  // index into tx_buf_ of the next unsent byte
        while (sent < tx_buf_.size()) {
            uint32_t in_flight = snd_nxt_ - snd_una_;
            uint32_t wnd = snd_wnd_ > in_flight ? snd_wnd_ - in_flight : 0;
            if (wnd == 0) break;
            size_t chunk = std::min<size_t>(ADVERTISED_MSS,
                                            std::min<size_t>(wnd, tx_buf_.size() - sent));
            if (chunk == 0) break;
            send_segment_(TH_ACK | TH_PSH, reinterpret_cast<const uint8_t*>(tx_buf_.data()) + sent,
                          chunk, nullptr, 0);
            sent += chunk;
            snd_nxt_ = wrap_add(snd_nxt_, static_cast<uint32_t>(chunk));
        }
        if (upstream_eof_ && sent == tx_buf_.size() && !fin_sent_) {
            fin_seq_value_ = snd_nxt_;
            send_segment_(TH_FIN | TH_ACK, nullptr, 0, nullptr, 0);
            fin_sent_ = true;
            snd_nxt_ = wrap_add(snd_nxt_, 1);
            // The FIN rides the same retransmission window as the data; only
            // arm a timer when nothing else is currently being timed.
            if (rto_deadline_ == 0) rto_deadline_ = TunProxy::monotonic_ms() + RTO_MS;
        }
        if (snd_nxt_ != snd_una_ && rto_deadline_ == 0)
            rto_deadline_ = TunProxy::monotonic_ms() + RTO_MS;
    }

    void retransmit_() {
        if (state_ == State::SYN_RCVD) {
            send_synack_();
            return;
        }
        if (snd_nxt_ == snd_una_) {
            if (fin_sent_ && !fin_acked_) {
                owner_->send_tcp(key_, fin_seq_value_, rcv_nxt_, TH_FIN | TH_ACK, nullptr, 0,
                                 rcv_window_(), nullptr, 0);
            }
            return;
        }
        // Retransmit from the oldest unacknowledged byte. tx_buf_ is indexed
        // from snd_una_, so the recovery segment must carry sequence snd_una_
        // (not snd_nxt_, which points past all data already sent).
        size_t chunk = std::min<size_t>(ADVERTISED_MSS, tx_buf_.size());
        if (chunk == 0) return;
        owner_->send_tcp(key_, snd_una_, rcv_nxt_, TH_ACK | TH_PSH,
                         reinterpret_cast<const uint8_t*>(tx_buf_.data()), chunk, rcv_window_(),
                         nullptr, 0);
    }

    // Drives the HTTP request parser/framer and appends proxy-ready bytes to
    // up_out_. Bodies are framed explicitly so a body can never be parsed as the
    // next pipelined request header.
    void pump_app_(int64_t now) {
        if (state_ == State::DEAD || sock_ < 0 || !connected_) return;
        // Backpressure: stop draining the client receive buffer once enough
        // rewritten bytes are waiting for Charles. Our receive window closes,
        // the client stops sending, and memory stays bounded.
        if (up_out_.size() >= FLOW_APP_CAP) return;

        if (!http_checked_ && !app_in_.empty()) {
            http_checked_ = true;
            // Every supported request starts with an alphabetic method token.
            // TLS ClientHello (0x16) and other binary protocols fail here and
            // get a clean RST instead of being buffered until timeout.
            if (!std::isalpha(static_cast<unsigned char>(app_in_[0]))) {
                die_(true);
                return;
            }
        }

        bool progressed = true;
        while (progressed && !app_in_.empty()) {
            progressed = false;
            if (phase_ == BodyPhase::REQUEST_HEADER) {
                RequestHeaderInfo info = analyze_request_header(
                    app_in_, ipv4_to_string(key_.dst_addr), key_.dst_port);
                if (info.result == RequestResult::incomplete) {
                    if (app_in_.size() > HTTP_MAX_HEADER) die_(true);  // header runaway
                    return;
                }
                if (info.result == RequestResult::too_large ||
                    info.result == RequestResult::invalid) {
                    // CONNECT, smuggling attempts and malformed HTTP are refused.
                    die_(true);
                    return;
                }
                if (!trace_flow_started_) {
                    trace_flow_started_ = true;
                    std::string src = ipv4_to_string(key_.client_addr) + ":" +
                                      std::to_string(key_.client_port);
                    std::string dst = ipv4_to_string(key_.dst_addr) + ":" +
                                      std::to_string(key_.dst_port);
                    owner_->report_trace("flow\t" + std::to_string(id_) + "\t" + src +
                                         "\t" + dst + "\t" + std::to_string(now));
                }
                std::string original_header = app_in_.substr(0, info.consumed);
                request_bytes_ += info.consumed;
                last_method_ = info.method;
                last_host_ = info.host.empty() ? ipv4_to_string(key_.dst_addr) : info.host;
                last_target_ = info.target;
                last_request_ms_ = now;
                resp_started_ms_ = now;
                owner_->report_trace("req\t" + std::to_string(id_) + "\t" + info.method +
                                     "\t" + last_host_ + "\t" + last_target_ + "\t" +
                                     preview_b64(original_header, 1024) + "\t" +
                                     std::to_string(now));
                up_out_ += info.rewritten;
                app_in_.erase(0, info.consumed);
                if (info.chunked) {
                    phase_ = BodyPhase::CHUNKED;
                } else if (info.has_content_length) {
                    if (static_cast<uint64_t>(info.content_length) > FLOW_APP_CAP) {
                        die_(true);
                        return;
                    }
                    body_remaining_ = info.content_length;
                    phase_ = body_remaining_ > 0 ? BodyPhase::CONTENT_LENGTH
                                                 : BodyPhase::REQUEST_HEADER;
                }
                progressed = true;
            } else if (phase_ == BodyPhase::CONTENT_LENGTH) {
                size_t n = std::min<int64_t>(body_remaining_, static_cast<int64_t>(app_in_.size()));
                if (n == 0) {
                    phase_ = BodyPhase::REQUEST_HEADER;
                    progressed = true;
                    continue;
                }
                up_out_.append(app_in_.data(), n);
                app_in_.erase(0, n);
                request_bytes_ += n;
                body_remaining_ -= static_cast<int64_t>(n);
                if (body_remaining_ == 0) phase_ = BodyPhase::REQUEST_HEADER;
                progressed = true;
            } else if (phase_ == BodyPhase::CHUNKED) {
                size_t hlen = 0;
                long long sz = parse_chunk_header(app_in_.data(), app_in_.size(), hlen);
                if (sz == -1) return;  // wait for the rest of the chunk-size line
                if (sz == -2) {
                    die_(true);
                    return;
                }
                if (static_cast<uint64_t>(sz) > FLOW_APP_CAP) {
                    die_(true);  // unreasonably large chunk: refuse rather than buffer
                    return;
                }
                if (sz == 0) {
                    // Last chunk: optional trailers terminated by CRLF CRLF.
                    std::string rest = app_in_.substr(hlen);
                    if (rest.size() >= 2 && rest[0] == '\r' && rest[1] == '\n') {
                        up_out_.append(app_in_.data(), hlen + 2);
                        app_in_.erase(0, hlen + 2);
                        request_bytes_ += hlen + 2;
                        phase_ = BodyPhase::REQUEST_HEADER;
                        progressed = true;
                        continue;
                    }
                    size_t term = rest.find("\r\n\r\n");
                    if (term == std::string::npos) return;
                    size_t take = hlen + term + 4;
                    up_out_.append(app_in_.data(), take);
                    app_in_.erase(0, take);
                    request_bytes_ += take;
                    phase_ = BodyPhase::REQUEST_HEADER;
                    progressed = true;
                    continue;
                }
                // Forward the whole chunk (size line + data + CRLF) untouched.
                size_t need = hlen + static_cast<size_t>(sz) + 2;
                if (app_in_.size() < need) return;
                up_out_.append(app_in_.data(), need);
                app_in_.erase(0, need);
                request_bytes_ += need;
                progressed = true;
            }
        }
    }

    void on_upstream_data_(const char* data, size_t len) {
        response_bytes_ += len;
        if (resp_parse_disabled_) return;
        resp_parse_buf_.append(data, len);
        if (resp_parse_buf_.size() > 256u * 1024u) {
            resp_parse_buf_.clear();
            resp_parse_disabled_ = true;
            return;
        }
        parse_responses_();
    }

    void parse_responses_() {
        while (!resp_parse_buf_.empty()) {
            if (!resp_header_parsed_) {
                size_t end = resp_parse_buf_.find("\r\n\r\n");
                if (end == std::string::npos) {
                    if (resp_parse_buf_.size() > 65536u) {
                        resp_parse_buf_.clear();
                        resp_parse_disabled_ = true;
                    }
                    return;
                }
                resp_header_raw_ = resp_parse_buf_.substr(0, end + 4);
                resp_parse_buf_.erase(0, end + 4);
                size_t line_end = resp_header_raw_.find("\r\n");
                resp_status_line_ = line_end == std::string::npos
                                        ? std::string()
                                        : resp_header_raw_.substr(0, line_end);
                resp_chunked_ = false;
                resp_has_content_length_ = false;
                resp_content_length_ = 0;
                resp_body_remaining_ = 0;
                resp_body_bytes_ = 0;
                resp_preview_.clear();
                resp_preview_emitted_ = false;
                resp_chunk_need_size_ = true;
                resp_chunk_need_crlf_ = false;
                resp_chunk_trailers_ = false;
                resp_chunk_remaining_ = 0;
                size_t pos = line_end == std::string::npos ? resp_header_raw_.size()
                                                           : line_end + 2;
                while (pos < resp_header_raw_.size()) {
                    size_t next = resp_header_raw_.find("\r\n", pos);
                    if (next == std::string::npos || next == pos) break;
                    std::string line = resp_header_raw_.substr(pos, next - pos);
                    size_t colon = line.find(':');
                    if (colon != std::string::npos) {
                        std::string name = ascii_lower_copy(trim_spaces(line.substr(0, colon)));
                        std::string value = trim_spaces(line.substr(colon + 1));
                        if (name == "content-length" && value.find(',') == std::string::npos) {
                            char* tail = nullptr;
                            unsigned long long parsed = std::strtoull(value.c_str(), &tail, 10);
                            if (tail != value.c_str() && *tail == '\0') {
                                resp_has_content_length_ = true;
                                resp_content_length_ = static_cast<size_t>(parsed);
                            }
                        } else if (name == "transfer-encoding" &&
                                   ascii_lower_copy(value) == "chunked") {
                            resp_chunked_ = true;
                        }
                    }
                    pos = next + 2;
                }
                // HEAD, 1xx, 204 and 304 responses never carry a body even
                // when they advertise Content-Length. Treat them as complete so
                // the parser does not stall before the next keep-alive response.
                std::string status_code;
                size_t sp1 = resp_status_line_.find(' ');
                if (sp1 != std::string::npos) {
                    size_t sp2 = resp_status_line_.find(' ', sp1 + 1);
                    status_code = resp_status_line_.substr(
                        sp1 + 1, sp2 == std::string::npos ? std::string::npos : sp2 - sp1 - 1);
                }
                bool bodyless = last_method_ == "HEAD" || status_code == "204" ||
                                status_code == "304" ||
                                (!status_code.empty() && status_code[0] == '1');
                if (bodyless) {
                    resp_chunked_ = false;
                    resp_has_content_length_ = true;
                    resp_content_length_ = 0;
                }
                resp_header_parsed_ = true;
                resp_until_close_ = !resp_chunked_ && !resp_has_content_length_;
                resp_body_remaining_ = resp_has_content_length_ ? resp_content_length_ : 0;
                current_resp_index_ = response_index_++;
                resp_started_ms_ = now_ms();
                owner_->report_trace(
                    "resp\t" + std::to_string(id_) + "\t" +
                    std::to_string(current_resp_index_) + "\t" +
                    base64_encode(resp_status_line_) + "\t" +
                    preview_b64(resp_header_raw_, 2048) + "\t" +
                    std::to_string(resp_content_length_) + "\t" +
                    std::to_string(resp_started_ms_));
                if (!resp_chunked_ && resp_has_content_length_ && resp_content_length_ == 0) {
                    finish_response_();
                }
                continue;
            }

            if (resp_chunked_) {
                if (resp_chunk_trailers_) {
                    if (resp_parse_buf_.compare(0, 2, "\r\n") == 0) {
                        resp_parse_buf_.erase(0, 2);
                        finish_response_();
                        continue;
                    }
                    size_t trailer_end = resp_parse_buf_.find("\r\n\r\n");
                    if (trailer_end == std::string::npos) return;
                    resp_parse_buf_.erase(0, trailer_end + 4);
                    finish_response_();
                    continue;
                }
                if (resp_chunk_need_crlf_) {
                    if (resp_parse_buf_.size() < 2) return;
                    resp_parse_buf_.erase(0, 2);
                    resp_chunk_need_crlf_ = false;
                    resp_chunk_need_size_ = true;
                    continue;
                }
                if (resp_chunk_need_size_) {
                    size_t line = resp_parse_buf_.find("\r\n");
                    if (line == std::string::npos) return;
                    size_t value = 0;
                    bool ok = line > 0;
                    for (size_t i = 0; i < line && ok; ++i) {
                        char c = resp_parse_buf_[i];
                        if (c == ';') break;
                        if (c >= '0' && c <= '9') value = value * 16 + static_cast<size_t>(c - '0');
                        else if (c >= 'a' && c <= 'f') value = value * 16 + static_cast<size_t>(c - 'a' + 10);
                        else if (c >= 'A' && c <= 'F') value = value * 16 + static_cast<size_t>(c - 'A' + 10);
                        else { ok = false; break; }
                    }
                    resp_parse_buf_.erase(0, line + 2);
                    if (!ok) {
                        resp_parse_disabled_ = true;
                        resp_parse_buf_.clear();
                        return;
                    }
                    if (value == 0) {
                        resp_chunk_need_size_ = false;
                        resp_chunk_trailers_ = true;
                        continue;
                    }
                    resp_chunk_remaining_ = value;
                    resp_chunk_need_size_ = false;
                    resp_chunk_need_crlf_ = false;
                }
                size_t take = std::min(resp_chunk_remaining_, resp_parse_buf_.size());
                if (take == 0) return;
                append_preview_(resp_parse_buf_.data(), take);
                resp_parse_buf_.erase(0, take);
                resp_chunk_remaining_ -= take;
                resp_body_bytes_ += take;
                maybe_emit_preview_();
                if (resp_chunk_remaining_ == 0) {
                    resp_chunk_need_crlf_ = true;
                }
                continue;
            }

            if (resp_until_close_) {
                if (!resp_parse_buf_.empty()) {
                    append_preview_(resp_parse_buf_.data(), resp_parse_buf_.size());
                    resp_body_bytes_ += resp_parse_buf_.size();
                    resp_parse_buf_.clear();
                    maybe_emit_preview_();
                }
                return;
            }

            if (resp_body_remaining_ == 0) {
                finish_response_();
                continue;
            }
            size_t take = std::min(resp_body_remaining_, resp_parse_buf_.size());
            if (take == 0) return;
            append_preview_(resp_parse_buf_.data(), take);
            resp_parse_buf_.erase(0, take);
            resp_body_remaining_ -= take;
            resp_body_bytes_ += take;
            maybe_emit_preview_();
            if (resp_body_remaining_ == 0) {
                finish_response_();
            }
        }
    }

    void append_preview_(const char* data, size_t len) {
        constexpr size_t PREVIEW_CAP = 1024;
        if (resp_preview_.size() < PREVIEW_CAP) {
            size_t take = std::min(len, PREVIEW_CAP - resp_preview_.size());
            resp_preview_.append(data, take);
        }
    }

    void maybe_emit_preview_() {
        if (resp_preview_emitted_ || resp_preview_.empty()) return;
        resp_preview_emitted_ = true;
        emit_body_trace_();
    }

    void finish_response_() {
        emit_body_trace_();
        resp_header_parsed_ = false;
        resp_chunked_ = false;
        resp_until_close_ = false;
        resp_has_content_length_ = false;
        resp_content_length_ = 0;
        resp_body_remaining_ = 0;
        resp_body_bytes_ = 0;
        resp_status_line_.clear();
        resp_header_raw_.clear();
        resp_preview_.clear();
        resp_preview_emitted_ = false;
        resp_chunk_need_size_ = true;
        resp_chunk_need_crlf_ = false;
        resp_chunk_trailers_ = false;
        resp_chunk_remaining_ = 0;
        resp_started_ms_ = 0;
    }

    void emit_body_trace_() {
        int64_t now = now_ms();
        int64_t duration = last_request_ms_ > 0 ? now - last_request_ms_ : 0;
        owner_->report_trace("body\t" + std::to_string(id_) + "\t" +
                             std::to_string(current_resp_index_) + "\t" +
                             preview_b64(resp_preview_, 1024) + "\t" +
                             std::to_string(resp_body_bytes_) + "\t" +
                             std::to_string(duration));
    }

    void report_close_() {
        if (!trace_flow_started_ || close_reported_) return;
        if (resp_header_parsed_ && resp_until_close_) {
            emit_body_trace_();
        }
        close_reported_ = true;
        int64_t now = now_ms();
        owner_->report_trace("close\t" + std::to_string(id_) + "\t" +
                             std::to_string(request_bytes_) + "\t" +
                             std::to_string(response_bytes_) + "\t" +
                             std::to_string(now - created_ms_));
    }

    void die_(bool send_reset) {
        if (state_ == State::DEAD) return;
        state_ = State::DEAD;
        if (send_reset) {
            owner_->send_tcp(key_, snd_nxt_, rcv_nxt_, TH_RST | TH_ACK, nullptr, 0, 0, nullptr, 0);
        }
        if (sock_ >= 0) {
            ::close(sock_);
            sock_ = -1;
        }
    }

    uint32_t fin_seq_value_ = 0;
};

// ---------------------------------------------------------------------------
// TunProxy
// ---------------------------------------------------------------------------

int64_t TunProxy::monotonic_ms() { return now_ms(); }

TunProxy::TunProxy() = default;

TunProxy::~TunProxy() { stop(); }

bool TunProxy::configure(const std::string& target_ip, uint16_t target_port, std::string& error) {
    std::lock_guard<std::mutex> guard(start_mutex_);
    if (running_.load()) {
        error = "cannot reconfigure while the proxy is running; call stopVpnProxy first";
        return false;
    }
    uint32_t addr = 0;
    if (!parse_ipv4(target_ip, addr)) {
        error = "targetIp must be a valid IPv4 dotted-quad address";
        return false;
    }
    if (target_port == 0) {
        error = "targetPort must be 1-65535";
        return false;
    }
    proxy_ip_text_ = target_ip;
    proxy_addr_ = addr;
    proxy_port_ = target_port;
    return true;
}

bool TunProxy::attach(int tun_fd, std::string& error) {
    std::lock_guard<std::mutex> guard(start_mutex_);
    if (running_.load() || worker_.joinable()) {
        error = "proxy already running or waiting for stopVpnProxy cleanup";
        return false;
    }
    if (proxy_port_ == 0) {
        error = "proxy target not configured";
        return false;
    }
    int dupfd = ::dup(tun_fd);
    if (dupfd < 0) {
        error = std::string("dup(tun_fd) failed: ") + std::strerror(errno);
        return false;
    }
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        error = std::string("wake pipe failed: ") + std::strerror(errno);
        ::close(dupfd);
        return false;
    }
    if (!set_nonblocking(dupfd) || !set_nonblocking(pipefd[0]) || !set_nonblocking(pipefd[1])) {
        error = "failed to set nonblocking flags";
        ::close(dupfd);
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        return false;
    }
    tun_fd_ = dupfd;
    wake_r_ = pipefd[0];
    wake_w_ = pipefd[1];
    running_.store(true);
    try {
        worker_ = std::thread([this]() {
            try {
                worker_loop();
            } catch (const std::exception& e) {
                report_event(std::string("fatal:Native转发异常：") + e.what());
                running_.store(false);
            } catch (...) {
                report_event("fatal:Native转发发生未知异常");
                running_.store(false);
            }
        });
    } catch (const std::exception& e) {
        running_.store(false);
        ::close(tun_fd_);
        ::close(wake_r_);
        ::close(wake_w_);
        tun_fd_ = wake_r_ = wake_w_ = -1;
        error = std::string("无法启动Native转发线程：") + e.what();
        return false;
    }
    return true;
}

void TunProxy::stop() {
    std::lock_guard<std::mutex> guard(start_mutex_);
    running_.store(false);
    if (wake_w_ >= 0) {
        char b = 1;
        ssize_t rc = ::write(wake_w_, &b, 1);
        (void)rc;
    }
    if (worker_.joinable()) worker_.join();
    if (tun_fd_ >= 0) {
        ::close(tun_fd_);
        tun_fd_ = -1;
    }
    if (wake_r_ >= 0) {
        ::close(wake_r_);
        wake_r_ = -1;
    }
    if (wake_w_ >= 0) {
        ::close(wake_w_);
        wake_w_ = -1;
    }
    // Flow/DnsEntry destructors close every outbound socket.
    flows_.clear();
    dns_.clear();
    reassembler_.clear();
}

void TunProxy::set_event_callback(EventCallback cb) {
    std::lock_guard<std::mutex> lock(cb_mutex_);
    event_cb_ = std::move(cb);
}

void TunProxy::report_event(const std::string& message) {
    EventCallback cb;
    {
        std::lock_guard<std::mutex> lock(cb_mutex_);
        cb = event_cb_;
    }
    if (cb) cb(message);
}

void TunProxy::report_trace(const std::string& payload) {
    LOGI("trace emit len=%zu kind=%.12s", payload.size(), payload.c_str());
    report_event("trace\t" + payload);
}

void TunProxy::emit_packet(const void* data, size_t len) {
    const auto* p = static_cast<const uint8_t*>(data);
    size_t off = 0;
    while (off < len) {
        ssize_t n = ::write(tun_fd_, p + off, len - off);
        if (n > 0) {
            off += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            // TUN backpressure: drop rather than spin. The TCP peers retransmit.
            LOGW("TUN write backpressure, dropping %zu byte packet", len - off);
            return;
        }
        if (n < 0) {
            report_event(std::string("TUN write failed: ") + std::strerror(errno));
            return;
        }
    }
}

void TunProxy::send_tcp(const FlowKey& k, uint32_t seq, uint32_t ack, uint8_t flags,
                        const uint8_t* data, size_t dlen, uint16_t window, const uint8_t* opts,
                        size_t opts_len) {
    if (tun_fd_ < 0) return;
    uint8_t pkt[20 + 20 + 40 + ADVERTISED_MSS];
    size_t tcp_hlen = 20 + opts_len;
    size_t total = 20 + tcp_hlen + dlen;
    if (total > sizeof(pkt)) return;

    auto* ip = reinterpret_cast<Ipv4Header*>(pkt);
    std::memset(ip, 0, 20);
    ip->version_ihl = 0x45;
    ip->tos = 0;
    ip->total_length = htons(static_cast<uint16_t>(total));
    ip->id = htons(++ip_id_);
    ip->flags_fragment = htons(IP_DF);
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP_V;
    ip->src_addr = k.dst_addr;  // answers appear to come from the original destination
    ip->dst_addr = k.client_addr;
    ip->checksum = 0;
    ip->checksum = htons(ip_checksum(ip));

    auto* th = reinterpret_cast<TcpHeader*>(pkt + 20);
    std::memset(th, 0, sizeof(TcpHeader));
    th->src_port = htons(k.dst_port);
    th->dst_port = htons(k.client_port);
    th->seq = htonl(seq);
    th->ack = htonl(ack);
    th->data_offset_flags =
        htons(static_cast<uint16_t>((tcp_hlen / 4) << 12 | flags));
    th->window = htons(window);
    th->urgent = 0;
    if (opts_len > 0) std::memcpy(pkt + 20 + 20, opts, opts_len);
    if (dlen > 0) std::memcpy(pkt + 20 + tcp_hlen, data, dlen);
    th->checksum = 0;
    th->checksum = htons(transport_checksum_v4(ip->src_addr, ip->dst_addr, IPPROTO_TCP_V,
                                                pkt + 20, tcp_hlen + dlen));
    emit_packet(pkt, total);
}

void TunProxy::send_rst(const Ipv4Header* ip, const TcpHeader* th, size_t seg_len) {
    FlowKey k{};
    k.client_addr = ip->src_addr;
    k.client_port = ntohs(th->src_port);
    k.dst_addr = ip->dst_addr;
    k.dst_port = ntohs(th->dst_port);
    uint8_t flags = ntohs(th->data_offset_flags) & 0xff;
    uint32_t ack = wrap_add(ntohl(th->seq), static_cast<uint32_t>(seg_len));
    if (flags & TH_ACK) {
        send_tcp(k, ntohl(th->ack), ack, TH_RST | TH_ACK, nullptr, 0, 0, nullptr, 0);
    } else {
        // A bare non-ACK segment (e.g. stray SYN) is answered with a plain RST.
        send_tcp(k, 0, ack, TH_RST, nullptr, 0, 0, nullptr, 0);
    }
}

void TunProxy::rebuild_pollfds(std::vector<pollfd>& fds) {
    fds.clear();
    fds.push_back({tun_fd_, POLLIN, 0});
    fds.push_back({wake_r_, POLLIN, 0});
    for (auto& kv : flows_) {
        short ev = kv.second->wanted_events();
        if (kv.second->sock() >= 0 && ev != 0) fds.push_back({kv.second->sock(), ev, 0});
    }
    for (auto& kv : dns_) {
        fds.push_back({kv.second->sock, POLLIN, 0});
    }
}

void TunProxy::worker_loop() {
    std::vector<pollfd> fds;
    uint8_t rbuf[65535];
    while (running_.load()) {
        rebuild_pollfds(fds);
        int rc = poll(fds.data(), fds.size(), 200);
        if (rc < 0) {
            if (errno == EINTR) continue;
            report_event(std::string("fatal:TUN事件循环失败：") + std::strerror(errno));
            break;
        }
        int64_t now = now_ms();

        if (fds.size() >= 2 && fds[1].revents != 0) {
            char drain[256];
            while (::read(wake_r_, drain, sizeof(drain)) > 0) {
            }
            if (!running_.load()) break;
        }

        if (fds[0].revents != 0) {
            for (;;) {
                ssize_t n = ::read(tun_fd_, rbuf, sizeof(rbuf));
                if (n > 0) {
                    handle_packet(rbuf, static_cast<size_t>(n), now);
                    continue;
                }
                if (n < 0 && errno == EINTR) continue;
                break;  // EAGAIN: drained the TUN queue
            }
        }

        // Socket events for flows and DNS relays.
        for (size_t i = 2; i < fds.size(); ++i) {
            if (fds[i].revents == 0) continue;
            int fd = fds[i].fd;
            bool handled = false;
            for (auto& kv : flows_) {
                if (kv.second->sock() == fd) {
                    kv.second->on_poll(fds[i].revents, now);
                    handled = true;
                    break;
                }
            }
            if (!handled) {
                auto dit = std::find_if(dns_.begin(), dns_.end(),
                                        [fd](const auto& kv) { return kv.second->sock == fd; });
                if (dit != dns_.end()) handle_dns_response_(dit->first, fds[i].revents);
            }
        }

        for (auto it = flows_.begin(); it != flows_.end();) {
            if (!it->second->tick(now))
                it = flows_.erase(it);
            else
                ++it;
        }
        for (auto it = dns_.begin(); it != dns_.end();) {
            if (now > it->second->deadline) {
                ::close(it->second->sock);
                it = dns_.erase(it);
            } else {
                ++it;
            }
        }
        reassembler_.sweep(now);
    }
    running_.store(false);
}

void TunProxy::handle_packet(const uint8_t* packet, size_t len, int64_t now) {
    if (len < sizeof(Ipv4Header)) return;
    auto* ip = reinterpret_cast<const Ipv4Header*>(packet);
    if ((ip->version_ihl >> 4) != 4) return;  // IPv6/other: not handled by this IPv4 endpoint
    size_t ihl = static_cast<size_t>(ip->version_ihl & 0x0f) * 4;
    if (ihl < 20 || ihl > len) return;
    uint16_t total = ntohs(ip->total_length);
    if (total < ihl || total > len) return;
    if (!verify_ip_checksum(packet, len)) return;

    uint16_t frag = ntohs(ip->flags_fragment);
    bool mf = (frag & IP_MF) != 0;
    uint16_t off = static_cast<uint16_t>((frag & IP_OFFMASK) * 8);
    if (mf || off != 0) {
        uint16_t id = ntohs(ip->id);
        std::string assembled;
        std::string reason;
        bool done = reassembler_.add_fragment(
            ip->src_addr, ip->dst_addr, ip->protocol, id, off, mf, packet + ihl, total - ihl, now,
            assembled, reason);
        if (!done) {
            if (!reason.empty()) LOGW("fragment rejected: %s", reason.c_str());
            return;
        }
        dispatch_transport_(ip, reinterpret_cast<const uint8_t*>(assembled.data()),
                            assembled.size(), now);
        return;
    }
    dispatch_transport_(ip, packet + ihl, total - ihl, now);
}

void TunProxy::dispatch_transport_(const Ipv4Header* ip, const uint8_t* transport, size_t tlen,
                                   int64_t now) {
    if (ip->protocol == IPPROTO_TCP_V)
        handle_tcp(ip, transport, tlen, now);
    else if (ip->protocol == IPPROTO_UDP_V)
        handle_udp(ip, transport, tlen, now);
    // All other protocols (ICMP, GRE, SCTP, ...) are dropped silently.
}

void TunProxy::handle_tcp(const Ipv4Header* ip, const uint8_t* transport, size_t tlen,
                          int64_t now) {
    if (tlen < sizeof(TcpHeader)) return;
    auto* th = reinterpret_cast<const TcpHeader*>(transport);
    size_t doff = static_cast<size_t>(ntohs(th->data_offset_flags) >> 12) * 4;
    if (doff < 20 || doff > tlen) return;
    size_t dlen = tlen - doff;
    uint8_t flags = ntohs(th->data_offset_flags) & 0xff;
    // SYN and FIN each consume one sequence number; plain data does not.
    size_t seg_len = dlen + ((flags & (TH_SYN | TH_FIN)) ? 1u : 0u);

    FlowKey key{};
    key.client_addr = ip->src_addr;
    key.client_port = ntohs(th->src_port);
    key.dst_addr = ip->dst_addr;
    key.dst_port = ntohs(th->dst_port);

    auto it = flows_.find(key);
    if (it == flows_.end()) {
        bool pure_syn = (flags & TH_SYN) && !(flags & TH_ACK) && dlen == 0;
        if (!pure_syn) {
            send_rst(ip, th, seg_len);
            return;
        }
        if (flows_.size() >= MAX_FLOWS) {
            LOGW("flow cap (%d) reached, RSTing new connection", MAX_FLOWS);
            send_rst(ip, th, seg_len);
            return;
        }
        LOGI("tcp flow dst=%s:%u", ipv4_to_string(key.dst_addr).c_str(), key.dst_port);
        auto flow = std::make_unique<Flow>(this, key);
        flow->on_syn(th, now);
        flows_.emplace(key, std::move(flow));
        return;
    }
    it->second->on_tcp(th, transport + doff, dlen, now);
}

void TunProxy::handle_udp(const Ipv4Header* ip, const uint8_t* transport, size_t tlen,
                          int64_t now) {
    if (tlen < sizeof(UdpHeader)) return;
    auto* uh = reinterpret_cast<const UdpHeader*>(transport);
    uint16_t dst = ntohs(uh->dst_port);
    uint16_t src = ntohs(uh->src_port);
    size_t ulen = ntohs(uh->length);
    if (ulen < sizeof(UdpHeader) || ulen > tlen) return;
    const uint8_t* payload = transport + sizeof(UdpHeader);
    size_t plen = ulen - sizeof(UdpHeader);

    // Only DNS (dst port 53) is relayed. Every other UDP datagram is dropped.
    // In practice this means QUIC/HTTP3 is not captured: browsers notice the
    // blocked UDP and fall back to TCP, which we do intercept. It is not
    // "passed directly" — there is no physical bypass path in this engine.
    if (dst != 53) return;
    if (plen < 12) return;  // not a DNS message
    if (dns_.size() >= 128) return;  // bounded outstanding DNS requests

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;
    if (!set_nonblocking(s)) {
        ::close(s);
        return;
    }
    sockaddr_in resolver{};
    resolver.sin_family = AF_INET;
    resolver.sin_addr.s_addr = ip->dst_addr;
    resolver.sin_port = htons(dst);
    // Connected UDP filters replies to the selected resolver address/port.
    if (::connect(s, reinterpret_cast<sockaddr*>(&resolver), sizeof(resolver)) != 0) {
        ::close(s);
        return;
    }
    ssize_t wr = send(s, payload, plen, 0);
    if (wr < 0) {
        ::close(s);
        return;
    }
    auto entry = std::make_unique<DnsEntry>();
    entry->sock = s;
    entry->client_addr = ip->src_addr;
    entry->client_port = src;
    entry->resolver_addr = ip->dst_addr;
    entry->deadline = now + DNS_TIMEOUT_MS;
    dns_.emplace(static_cast<uint64_t>(s), std::move(entry));
}

void TunProxy::handle_dns_response_(uint64_t key, short revents) {
    auto it = dns_.find(key);
    if (it == dns_.end()) return;
    DnsEntry& e = *it->second;
    if (revents & (POLLERR | POLLNVAL)) {
        ::close(e.sock);
        dns_.erase(it);
        return;
    }
    uint8_t buf[4096];
    ssize_t n = ::recv(e.sock, buf, sizeof(buf), 0);
    if (n <= 0) {
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        ::close(e.sock);
        dns_.erase(it);
        return;
    }
    // Rebuild the UDP/IP reply as if it came from the original resolver.
    uint8_t pkt[20 + 8 + sizeof(buf)];
    size_t total = 20 + 8 + static_cast<size_t>(n);
    auto* ip = reinterpret_cast<Ipv4Header*>(pkt);
    std::memset(ip, 0, 20);
    ip->version_ihl = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(total));
    ip->id = htons(++ip_id_);
    ip->flags_fragment = htons(IP_DF);
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP_V;
    ip->src_addr = e.resolver_addr;
    ip->dst_addr = e.client_addr;
    ip->checksum = htons(ip_checksum(ip));

    auto* uh = reinterpret_cast<UdpHeader*>(pkt + 20);
    uh->src_port = htons(53);
    uh->dst_port = htons(e.client_port);
    uh->length = htons(static_cast<uint16_t>(8 + n));
    uh->checksum = 0;  // optional over IPv4; zero means "not computed"
    std::memcpy(pkt + 28, buf, static_cast<size_t>(n));
    emit_packet(pkt, total);

    ::close(e.sock);
    dns_.erase(it);
}

}  // namespace charles
