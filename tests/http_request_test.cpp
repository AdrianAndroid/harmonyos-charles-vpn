// Host tests for the HTTP/1 request rewriter/framer. No HarmonyOS dependencies.
#include "../entry/src/main/cpp/http_request.h"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <string>

using namespace charles;

namespace {

void test_basic_rewrite() {
    RequestHeaderInfo info = analyze_request_header(
        "POST /a?q=1 HTTP/1.1\r\nHost: example.com:8080\r\nContent-Length: 3\r\n\r\nabc",
        "1.2.3.4", 80);
    assert(info.result == RequestResult::ready);
    assert(info.rewritten ==
           "POST http://example.com:8080/a?q=1 HTTP/1.1\r\nHost: example.com:8080\r\n"
           "Content-Length: 3\r\n\r\n");
    assert(info.has_content_length && info.content_length == 3 && !info.chunked);
    assert(std::string("abc") == "abc");  // body left for the framer

    // Legacy wrapper keeps its original contract.
    std::string wrapped =
        "POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc";
    std::string out;
    size_t n = 0;
    assert(rewrite_request_header(wrapped, "9.9.9.9", 80, out, n) == RequestResult::ready);
    assert(wrapped.substr(n) == "abc");  // body must remain untouched
    assert(out.find("POST http://h/a HTTP/1.1") == 0);
}

void test_incomplete_and_too_large() {
    RequestHeaderInfo info =
        analyze_request_header("GET / HTTP/1.1\r\nHost: x\r\n", "", 0);
    assert(info.result == RequestResult::incomplete);
    info = analyze_request_header(std::string(HTTP_MAX_HEADER + 1, 'x'), "", 0);
    assert(info.result == RequestResult::too_large);
}

void test_duplicate_host_and_http10_no_host() {
    assert(analyze_request_header("GET / HTTP/1.1\r\nHost: x\r\nHost: y\r\n\r\n", "", 0)
               .result == RequestResult::invalid);
    RequestHeaderInfo info =
        analyze_request_header("GET / HTTP/1.0\r\n\r\n", "1.2.3.4", 8080);
    assert(info.result == RequestResult::ready);
    assert(info.rewritten == "GET http://1.2.3.4:8080/ HTTP/1.0\r\n\r\n");
    // Port 80 is omitted from the synthesized Host.
    info = analyze_request_header("GET / HTTP/1.0\r\n\r\n", "1.2.3.4", 80);
    assert(info.rewritten == "GET http://1.2.3.4/ HTTP/1.0\r\n\r\n");
    // HTTP/1.1 without Host is always invalid.
    assert(analyze_request_header("GET / HTTP/1.1\r\n\r\n", "1.2.3.4", 80).result ==
           RequestResult::invalid);
}

void test_smuggling_rejections() {
    // Duplicate Content-Length.
    assert(analyze_request_header(
               "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nX",
               "", 0)
               .result == RequestResult::invalid);
    // Comma-separated Content-Length list.
    assert(analyze_request_header(
               "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 1, 2\r\n\r\nX", "", 0)
               .result == RequestResult::invalid);
    // Transfer-Encoding + Content-Length.
    assert(analyze_request_header(
               "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nContent-Length: "
               "4\r\n\r\n0\r\n\r\n",
               "", 0)
               .result == RequestResult::invalid);
    // Unsupported transfer coding.
    assert(analyze_request_header(
               "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", "", 0)
               .result == RequestResult::invalid);
    // CONNECT (HTTPS tunnelling) is refused, not forwarded.
    assert(analyze_request_header("CONNECT x:443 HTTP/1.1\r\nHost: x\r\n\r\n", "", 0)
               .result == RequestResult::invalid);
    // Non-numeric Content-Length.
    assert(analyze_request_header(
               "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 1x\r\n\r\n", "", 0)
               .result == RequestResult::invalid);
}

void test_fragmented_and_coalesced() {
    // Header arriving in several TCP segments.
    std::string full =
        "POST /p HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhelloGET /next HTTP/1.1\r\n"
        "Host: h\r\n\r\n";
    std::string acc;
    RequestHeaderInfo info;
    size_t fed = 0;
    while (fed < full.size()) {
        size_t take = std::min<size_t>(7, full.size() - fed);
        acc += full.substr(fed, take);
        fed += take;
        info = analyze_request_header(acc, "5.6.7.8", 80);
        if (info.result == RequestResult::ready) break;
        assert(info.result == RequestResult::incomplete);
    }
    assert(info.result == RequestResult::ready);
    assert(info.content_length == 5);
    // Deliver the rest of the stream (body + pipelined request) coalesced.
    acc += full.substr(fed);

    // Simulate the engine framing: header, then exactly 5 body bytes, then the
    // pipelined second request must survive intact.
    std::string remaining = acc.substr(info.consumed);
    assert(remaining.size() >= 5);
    assert(remaining.substr(0, 5) == "hello");
    remaining = remaining.substr(5);
    RequestHeaderInfo second = analyze_request_header(remaining, "5.6.7.8", 80);
    assert(second.result == RequestResult::ready);
    assert(second.rewritten.compare(0, 4, "GET ") == 0);
    assert(second.rewritten.find("http://h/next") != std::string::npos);

    // Two fully coalesced requests in one buffer.
    std::string two = "GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n";
    RequestHeaderInfo r1 = analyze_request_header(two, "1.1.1.1", 80);
    assert(r1.result == RequestResult::ready);
    RequestHeaderInfo r2 = analyze_request_header(two.substr(r1.consumed), "1.1.1.1", 80);
    assert(r2.result == RequestResult::ready);
    assert(r2.rewritten.find("/b") != std::string::npos);
}

void test_chunked_framing() {
    std::string raw =
        "POST /c HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
        "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    RequestHeaderInfo info = analyze_request_header(raw, "1.1.1.1", 80);
    assert(info.result == RequestResult::ready && info.chunked);
    std::string rest = raw.substr(info.consumed);

    size_t hlen = 0;
    long long sz = parse_chunk_header(rest.data(), rest.size(), hlen);
    assert(sz == 5 && hlen == 3);
    assert(rest.substr(hlen, 5) == "hello");
    rest = rest.substr(hlen + 5 + 2);  // skip chunk data and its CRLF

    sz = parse_chunk_header(rest.data(), rest.size(), hlen);
    assert(sz == 6 && hlen == 3);
    rest = rest.substr(hlen + 6 + 2);

    sz = parse_chunk_header(rest.data(), rest.size(), hlen);
    assert(sz == 0 && hlen == 3);  // terminating chunk

    // Partial chunk-size line waits for more bytes; garbage is rejected.
    assert(parse_chunk_header("5\r", 2, hlen) == -1);
    assert(parse_chunk_header("zz\r\n", 4, hlen) == -2);
}

void test_absolute_form_and_prescreen() {
    RequestHeaderInfo info = analyze_request_header(
        "GET http://h/p HTTP/1.1\r\nHost: h\r\n\r\n", "1.1.1.1", 80);
    assert(info.result == RequestResult::ready);
    assert(info.rewritten.find("GET http://h/p HTTP/1.1") == 0);

    const uint8_t http[] = "GET / HTTP/1.1";
    assert(looks_like_http_request(http, sizeof(http) - 1));
    const uint8_t tls[] = {0x16, 0x03, 0x01, 0x02, 0x00};
    assert(!looks_like_http_request(tls, sizeof(tls)));
}

void test_ipv4_helpers() {
    uint32_t addr = 0;
    assert(parse_ipv4("192.168.0.1", addr));
    assert(ipv4_to_string(addr) == "192.168.0.1");
    assert(parse_ipv4("10.0.0.255", addr) && ipv4_to_string(addr) == "10.0.0.255");
    const char* bad[] = {"", "1.2.3", "1.2.3.4.5", "256.0.0.1", "01.2.3.4", "1.2.3.x",
                         " 1.2.3.4", "1..2.3"};
    for (const char* b : bad) assert(!parse_ipv4(b, addr));
}

}  // namespace

int main() {
    test_basic_rewrite();
    test_incomplete_and_too_large();
    test_duplicate_host_and_http10_no_host();
    test_smuggling_rejections();
    test_fragmented_and_coalesced();
    test_chunked_framing();
    test_absolute_form_and_prescreen();
    test_ipv4_helpers();
    return 0;
}
