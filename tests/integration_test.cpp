// End-to-end host test for the userspace TCP/HTTP stack.
//
// A socketpair stands in for the TUN device (stream semantics are identical for
// the framed IP packets the engine reads and writes). A local TCP server plays
// Charles. The test implements just enough of a TCP client to complete the
// handshake, send an origin-form GET, ACK the response and observe the FIN.
#include "../entry/src/main/cpp/tun_proxy.h"

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cassert>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace charles;

namespace {

constexpr uint8_t TH_SYN = 0x02;
constexpr uint8_t TH_ACK = 0x10;
constexpr uint8_t TH_PSH = 0x08;
constexpr uint8_t TH_FIN = 0x01;
constexpr uint8_t TH_RST = 0x04;

uint32_t CLIENT_IP = 0;   // initialized in main via inet_addr
uint32_t DEST_IP = 0;

void build_packet(std::string& out, uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack,
                  uint8_t flags, const std::string& payload, uint32_t src, uint32_t dst,
                  uint8_t protocol) {
    size_t l4 = protocol == IPPROTO_TCP_V ? 20 + payload.size() : 8 + payload.size();
    out.resize(20 + l4);
    std::memset(out.data(), 0, out.size());
    auto* ip = reinterpret_cast<Ipv4Header*>(out.data());
    ip->version_ihl = 0x45;
    ip->total_length = htons(static_cast<uint16_t>(out.size()));
    ip->id = htons(1);
    ip->ttl = 64;
    ip->protocol = protocol;
    ip->src_addr = src;
    ip->dst_addr = dst;
    ip->checksum = htons(ip_checksum(ip));
    if (protocol == IPPROTO_TCP_V) {
        auto* th = reinterpret_cast<TcpHeader*>(out.data() + 20);
        th->src_port = htons(sport);
        th->dst_port = htons(dport);
        th->seq = htonl(seq);
        th->ack = htonl(ack);
        th->data_offset_flags = htons((5u << 12) | flags);
        th->window = htons(65535);
        if (!payload.empty()) std::memcpy(out.data() + 40, payload.data(), payload.size());
        th->checksum = htons(transport_checksum_v4(src, dst, IPPROTO_TCP_V,
                                                   reinterpret_cast<const uint8_t*>(th), l4));
    }
}

std::string b64decode(const std::string& input) {
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int lookup[256];
    for (int& value : lookup) value = -1;
    for (int i = 0; i < 64; ++i) lookup[static_cast<unsigned char>(table[i])] = i;
    std::string out;
    uint32_t buffer = 0;
    int bits = 0;
    for (char c : input) {
        if (c == '=') break;
        int value = lookup[static_cast<unsigned char>(c)];
        if (value < 0) continue;
        buffer = (buffer << 6) | static_cast<uint32_t>(value);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((buffer >> bits) & 0xff));
        }
    }
    return out;
}

bool wait_readable(int fd, int timeout_ms) {
    pollfd pfd{fd, POLLIN, 0};
    int rc = poll(&pfd, 1, timeout_ms);
    return rc > 0 && (pfd.revents & POLLIN);
}

// Read one framed IP packet, handling stream coalescing.
bool read_packet(int fd, std::string& pkt) {
    static thread_local std::string carry;
    for (;;) {
        if (carry.size() >= 20) {
            uint16_t total = ntohs(reinterpret_cast<const Ipv4Header*>(carry.data())->total_length);
            if (carry.size() >= total) {
                pkt = carry.substr(0, total);
                carry.erase(0, total);
                return true;
            }
        }
        if (!wait_readable(fd, 3000)) return false;
        char buf[4096];
        ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n <= 0) return false;
        carry.append(buf, static_cast<size_t>(n));
    }
}

struct ServerCtx {
    int port = 0;
    bool got_absolute_form = false;
    bool chunked = false;
    std::string received;
};

void charles_server(ServerCtx* ctx) {
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    bind(lfd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    socklen_t alen = sizeof(addr);
    getsockname(lfd, reinterpret_cast<sockaddr*>(&addr), &alen);
    ctx->port = ntohs(addr.sin_port);
    listen(lfd, 1);

    int cfd = accept(lfd, nullptr, nullptr);
    close(lfd);
    std::string req;
    while (req.find("\r\n\r\n") == std::string::npos) {
        char buf[1024];
        ssize_t n = ::read(cfd, buf, sizeof(buf));
        if (n <= 0) break;
        req.append(buf, static_cast<size_t>(n));
    }
    ctx->received = req;
    ctx->got_absolute_form = req.find("GET http://example.com/ HTTP/1.1") == 0;
    const std::string resp = ctx->chunked
                                 ? "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                                   "5\r\nhello\r\n0\r\n\r\n"
                                 : "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    const char* p = resp.data();
    size_t left = resp.size();
    if (ctx->chunked) {
        // Split the chunked framing across many upstream reads so the trace
        // parser must retain partial chunk-size/CRLF state.
        for (size_t i = 0; i < resp.size(); ++i) {
            if (::write(cfd, resp.data() + i, 1) != 1) break;
            usleep(1000);
        }
    } else {
        while (left > 0) {
            ssize_t n = ::write(cfd, p, left);
            if (n <= 0) break;
            p += n;
            left -= static_cast<size_t>(n);
        }
    }
    shutdown(cfd, SHUT_WR);  // upstream EOF -> proxy must FIN after the data
    close(cfd);
}

bool run_full_flow(bool delay_first_ack, bool chunked) {
    const bool want_retrans = delay_first_ack;
    ServerCtx ctx;
    ctx.chunked = chunked;
    std::thread server(charles_server, &ctx);
    while (ctx.port == 0) usleep(5000);

    // SOCK_DGRAM preserves one-packet-per-read semantics, matching a TUN fd.
    int sp[2];
    assert(socketpair(AF_LOCAL, SOCK_DGRAM, 0, sp) == 0);

    TunProxy proxy;
    std::mutex trace_mutex;
    std::vector<std::string> traces;
    proxy.set_event_callback([&](const std::string& message) {
        std::lock_guard<std::mutex> guard(trace_mutex);
        traces.push_back(message);
    });
    std::string err;
    assert(proxy.configure("127.0.0.1", static_cast<uint16_t>(ctx.port), err));
    assert(proxy.attach(sp[1], err));
    assert(proxy.is_running());
    close(sp[1]);  // engine works on its dup()

    const uint16_t sport = 40000;
    const uint16_t dport = 80;
    uint32_t cli_seq = 1000;
    uint32_t proxy_iss = 0;

    // SYN
    std::string pkt;
    build_packet(pkt, sport, dport, cli_seq, 0, TH_SYN, "", CLIENT_IP, DEST_IP, IPPROTO_TCP_V);
    assert(::write(sp[0], pkt.data(), pkt.size()) == static_cast<ssize_t>(pkt.size()));

    // SYNACK
    assert(read_packet(sp[0], pkt));
    auto* th = reinterpret_cast<const TcpHeader*>(pkt.data() + 20);
    assert((ntohs(th->data_offset_flags) & 0xff) == (TH_SYN | TH_ACK));
    assert(ntohl(th->ack) == cli_seq + 1);
    proxy_iss = ntohl(th->seq);
    cli_seq += 1;
    uint32_t proxy_next = proxy_iss + 1;  // SYN consumed one byte

    // Handshake ACK + GET in two writes (also exercises split delivery).
    build_packet(pkt, sport, dport, cli_seq, proxy_next, TH_ACK, "", CLIENT_IP, DEST_IP,
                 IPPROTO_TCP_V);
    assert(::write(sp[0], pkt.data(), pkt.size()) == static_cast<ssize_t>(pkt.size()));

    const std::string request =
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    build_packet(pkt, sport, dport, cli_seq, proxy_next, TH_ACK | TH_PSH, request, CLIENT_IP,
                 DEST_IP, IPPROTO_TCP_V);
    assert(::write(sp[0], pkt.data(), pkt.size()) == static_cast<ssize_t>(pkt.size()));
    cli_seq += static_cast<uint32_t>(request.size());

    // Collect response segments, ACKing each. With delay_first_ack the first ACK
    // is held past RTO_MS so the engine must retransmit the unacked segment.
    std::string body;
    bool saw_fin = false;
    bool saw_retransmission = false;
    int guard = 0;
    while (!saw_fin && guard++ < 400) {
        if (!read_packet(sp[0], pkt)) break;
        th = reinterpret_cast<const TcpHeader*>(pkt.data() + 20);
        uint8_t flags = static_cast<uint8_t>(ntohs(th->data_offset_flags) & 0xff);
        assert(!(flags & TH_RST));
        size_t doff = static_cast<size_t>(ntohs(th->data_offset_flags) >> 12) * 4;
        uint32_t seg_seq = ntohl(th->seq);
        size_t dlen = pkt.size() - 20 - doff;

        if (dlen > 0) {
            if (seg_seq < proxy_next) {
                // Retransmission must restart at the oldest unacked byte.
                saw_retransmission = true;
            } else {
                assert(seg_seq == proxy_next);
                body.append(pkt.data() + 20 + doff, dlen);
                proxy_next = seg_seq + static_cast<uint32_t>(dlen);
            }
            if (delay_first_ack) {
                usleep(2500 * 1000);  // well past RTO_MS plus poll granularity
                delay_first_ack = false;
            }
            build_packet(pkt, sport, dport, cli_seq, proxy_next, TH_ACK, "", CLIENT_IP, DEST_IP,
                         IPPROTO_TCP_V);
            assert(::write(sp[0], pkt.data(), pkt.size()) == static_cast<ssize_t>(pkt.size()));
        }
        if (flags & TH_FIN) {
            assert(ntohl(th->seq) + static_cast<uint32_t>(dlen) == proxy_next);
            saw_fin = true;
            build_packet(pkt, sport, dport, cli_seq, proxy_next + 1, TH_ACK, "", CLIENT_IP,
                         DEST_IP, IPPROTO_TCP_V);
            assert(::write(sp[0], pkt.data(), pkt.size()) == static_cast<ssize_t>(pkt.size()));
            // In the delayed-ACK run the unacked data retransmission is queued
            // behind the FIN; drain it. Skip the blocking read otherwise.
            if (want_retrans) {
                std::string extra;
                if (read_packet(sp[0], extra)) {
                    auto* eth = reinterpret_cast<const TcpHeader*>(extra.data() + 20);
                    if (ntohl(eth->seq) < proxy_next) saw_retransmission = true;
                }
            }
        }
    }
    assert(saw_fin);
    const std::string expected = chunked
                                     ? "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                                       "5\r\nhello\r\n0\r\n\r\n"
                                     : "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    assert(body == expected);

    proxy.stop();
    assert(!proxy.is_running());
    proxy.stop();  // idempotent
    close(sp[0]);
    server.join();

    assert(ctx.got_absolute_form);

    bool saw_flow = false;
    bool saw_req = false;
    bool saw_resp = false;
    bool saw_body = false;
    bool saw_full_body = false;
    bool saw_close = false;
    std::lock_guard<std::mutex> trace_guard(trace_mutex);
    for (const std::string& message : traces) {
        if (message.rfind("trace\t", 0) != 0) continue;
        if (message.find("trace\tflow\t") == 0) saw_flow = true;
        if (message.find("trace\treq\t") == 0) {
            saw_req = true;
            assert(message.find("\tGET\texample.com\t/\t") != std::string::npos);
        }
        if (message.find("trace\tresp\t") == 0) {
            saw_resp = true;
            if (!chunked) {
                assert(message.find("\t5\t") != std::string::npos);
            }
        }
        if (message.find("trace\tbody\t") == 0) {
            saw_body = true;
            std::string body_b64;
            size_t start = 0;
            for (int field = 0; field < 4; ++field) {
                start = message.find('\t', start);
                assert(start != std::string::npos);
                ++start;
            }
            size_t end = message.find('\t', start);
            body_b64 = message.substr(start, end == std::string::npos ? std::string::npos
                                                                     : end - start);
            if (b64decode(body_b64) == "hello") saw_full_body = true;
        }
        if (message.find("trace\tclose\t") == 0) saw_close = true;
    }
    assert(saw_flow);
    assert(saw_req);
    assert(saw_resp);
    assert(saw_body);
    assert(saw_full_body);
    assert(saw_close);

    return saw_retransmission;
}

void test_configure_validation() {
    TunProxy proxy;
    std::string err;
    assert(!proxy.configure("not.an.ip.addr", 8080, err));
    assert(!proxy.configure("127.0.0.1", 0, err));
    assert(proxy.configure("127.0.0.1", 8080, err));
    assert(!proxy.is_running());
    int sp[2];
    assert(socketpair(AF_LOCAL, SOCK_DGRAM, 0, sp) == 0);
    assert(!proxy.attach(-1, err));
    close(sp[0]);
    close(sp[1]);
    proxy.stop();  // never attached: must be a safe no-op
}

}  // namespace

int main() {
    CLIENT_IP = inet_addr("10.0.0.1");
    DEST_IP = inet_addr("1.2.3.4");
    test_configure_validation();
    run_full_flow(false, false);            // normal in-order path
    assert(run_full_flow(true, false));     // withheld ACK must force a retransmit
    run_full_flow(false, true);             // chunked response preview
    return 0;
}
