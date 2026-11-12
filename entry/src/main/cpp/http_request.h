#pragma once
#include <cstddef>
#include <cstdint>
#include <string>

namespace charles {

enum class RequestResult { incomplete, ready, invalid, too_large };

// Maximum accepted size of one HTTP request header block (64 KiB).
constexpr size_t HTTP_MAX_HEADER = 65536;

// Full analysis of one request header block. The engine needs the framing
// metadata in addition to the rewritten bytes so request bodies are never
// mistaken for the next pipelined request.
struct RequestHeaderInfo {
    RequestResult result = RequestResult::incomplete;
    size_t consumed = 0;              // header block length (\r\n\r\n included) when ready
    std::string rewritten;            // absolute-form header block when ready
    std::string method;
    std::string host;
    std::string target;               // raw request-target from the request line
    bool chunked = false;             // Transfer-Encoding: chunked
    bool has_content_length = false;
    int64_t content_length = 0;       // valid only when has_content_length
};

// Analyze and rewrite one complete HTTP/1 request header to proxy absolute-form.
// destination_ip/port identify the TUN flow destination and supply the Host for
// legacy HTTP/1.0 requests that carry none. The body is never touched; the
// caller frames it with the returned metadata before looking for the next
// pipelined request.
RequestHeaderInfo analyze_request_header(const std::string& input, const std::string& destination_ip,
                                         uint16_t destination_port);

// Backwards-compatible convenience wrapper around analyze_request_header.
RequestResult rewrite_request_header(const std::string& input, const std::string& destination_ip,
                                     uint16_t destination_port, std::string& output,
                                     size_t& consumed);

// Cheap pre-screen used before buffering a whole flow: does the start of this
// byte stream look like an HTTP/1.x request line?
bool looks_like_http_request(const uint8_t* data, size_t len);

// Parse one chunk-size line "1a3;ext\r\n" at data[0..len). On success returns
// the non-negative chunk size (0 marks the terminating chunk) and sets
// header_len to the number of bytes up to and including the trailing CRLF.
// Returns -1 when more bytes are needed, -2 on a malformed chunk header.
long long parse_chunk_header(const char* data, size_t len, size_t& header_len);

// Strict dotted-quad IPv4 validation ("1.2.3.4", no whitespace, no leading
// whitespace tolerance). Writes the network-order address on success.
bool parse_ipv4(const std::string& text, uint32_t& network_order);

std::string ipv4_to_string(uint32_t network_order);

}  // namespace charles
