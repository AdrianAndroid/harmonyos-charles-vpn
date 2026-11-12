#include "http_request.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace charles {
namespace {

bool token_char(unsigned char c) {
    return std::isalnum(c) || std::string("!#$%&'*+-.^_`|~").find(c) != std::string::npos;
}

std::string ascii_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string trim_ws(const std::string& s) {
    size_t a = s.find_first_not_of(" \t");
    size_t b = s.find_last_not_of(" \t");
    return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}

bool is_digits(const std::string& s) {
    return !s.empty() && std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; });
}

}  // namespace

RequestHeaderInfo analyze_request_header(const std::string& input, const std::string& ip,
                                         uint16_t port) {
    RequestHeaderInfo info;
    size_t end = input.find("\r\n\r\n");
    if (end == std::string::npos) {
        info.result = input.size() > HTTP_MAX_HEADER ? RequestResult::too_large
                                                     : RequestResult::incomplete;
        return info;
    }
    if (end + 4 > HTTP_MAX_HEADER) {
        info.result = RequestResult::too_large;
        return info;
    }
    info.consumed = end + 4;

    size_t line = input.find("\r\n");
    if (line == std::string::npos || line > end) {
        info.result = RequestResult::invalid;
        return info;
    }
    std::string first = input.substr(0, line);
    size_t a = first.find(' ');
    size_t b = a == std::string::npos ? a : first.find(' ', a + 1);
    if (a == std::string::npos || b == std::string::npos ||
        first.find(' ', b + 1) != std::string::npos || a == 0 || b == a + 1) {
        info.result = RequestResult::invalid;
        return info;
    }
    info.method = first.substr(0, a);
    std::string target = first.substr(a + 1, b - a - 1);
    std::string version = first.substr(b + 1);
    info.target = target;
    if (!std::all_of(info.method.begin(), info.method.end(), token_char) ||
        (version != "HTTP/1.1" && version != "HTTP/1.0") || info.method == "CONNECT") {
        info.result = RequestResult::invalid;
        return info;
    }
    for (unsigned char c : target) {
        if (c <= 32 || c == 127) {
            info.result = RequestResult::invalid;
            return info;
        }
    }

    bool host_seen = false;
    bool cl_seen = false;
    bool te_seen = false;
    std::string cl_raw;

    size_t pos = line + 2;
    while (pos < end) {
        size_t next = input.find("\r\n", pos);
        if (next == std::string::npos || next > end) {
            info.result = RequestResult::invalid;
            return info;
        }
        std::string h = input.substr(pos, next - pos);
        size_t colon = h.find(':');
        if (colon == std::string::npos || colon == 0 ||
            !std::all_of(h.begin(), h.begin() + colon, token_char)) {
            info.result = RequestResult::invalid;
            return info;
        }
        for (size_t i = colon + 1; i < h.size(); ++i) {
            if ((static_cast<unsigned char>(h[i]) < 32 && h[i] != '\t') || h[i] == 127) {
                info.result = RequestResult::invalid;
                return info;
            }
        }
        std::string name = ascii_lower(h.substr(0, colon));
        std::string value = trim_ws(h.substr(colon + 1));

        if (name == "host") {
            // Duplicate Host headers are ambiguous and rejected.
            if (host_seen) {
                info.result = RequestResult::invalid;
                return info;
            }
            host_seen = true;
            info.host = value;
            if (info.host.empty() || info.host.find_first_of(" \t/@?#\\") != std::string::npos) {
                info.result = RequestResult::invalid;
                return info;
            }
        } else if (name == "content-length") {
            // Request smuggling defence: exactly one Content-Length header,
            // one decimal integer, no comma-separated list of values.
            if (cl_seen || value.find(',') != std::string::npos) {
                info.result = RequestResult::invalid;
                return info;
            }
            cl_seen = true;
            cl_raw = value;
        } else if (name == "transfer-encoding") {
            // Only the single, exact "chunked" coding is accepted. Anything
            // else (gzip codings, multiple TE headers, whitespace tricks) is
            // rejected rather than guessed at.
            if (te_seen) {
                info.result = RequestResult::invalid;
                return info;
            }
            te_seen = true;
            if (ascii_lower(value) != "chunked") {
                info.result = RequestResult::invalid;
                return info;
            }
        }
        pos = next + 2;
    }

    // TE + CL in the same request is the classic request-smuggling pattern:
    // reject it outright instead of picking a framing.
    if (te_seen && cl_seen) {
        info.result = RequestResult::invalid;
        return info;
    }
    info.chunked = te_seen;
    if (cl_seen) {
        if (!is_digits(cl_raw)) {
            info.result = RequestResult::invalid;
            return info;
        }
        // Bounded parse: reject overflow instead of wrapping.
        int64_t v = 0;
        for (char c : cl_raw) {
            if (v > (INT64_MAX - (c - '0')) / 10) {
                info.result = RequestResult::invalid;
                return info;
            }
            v = v * 10 + (c - '0');
        }
        info.has_content_length = true;
        info.content_length = v;
    }

    if (!host_seen) {
        if (version == "HTTP/1.1" || ip.empty() || port == 0) {
            info.result = RequestResult::invalid;
            return info;
        }
        info.host = ip + (port == 80 ? "" : ":" + std::to_string(port));
    }

    if (target.compare(0, 7, "http://") != 0) {
        if (target.empty() || target[0] != '/') {
            // Authority-form (HTTPS CONNECT) and asterisk-form are not supported.
            info.result = RequestResult::invalid;
            return info;
        }
        target = "http://" + info.host + target;
    }

    info.rewritten = info.method + " " + target + " " + version +
                     input.substr(line, end + 4 - line);
    info.result = RequestResult::ready;
    return info;
}

RequestResult rewrite_request_header(const std::string& input, const std::string& ip,
                                     uint16_t port, std::string& output, size_t& consumed) {
    RequestHeaderInfo info = analyze_request_header(input, ip, port);
    output = info.rewritten;
    consumed = info.consumed;
    return info.result;
}

bool looks_like_http_request(const uint8_t* data, size_t len) {
    if (data == nullptr || len < 4) return false;
    size_t sp = 0;
    while (sp < len && sp < 16) {
        if (data[sp] == ' ') break;
        if (!std::isalpha(data[sp])) return false;
        ++sp;
    }
    if (sp == 0 || sp >= len || sp >= 16 || sp + 1 >= len) return false;
    // Origin-form ("/path") or absolute-form ("http://..."); nothing else.
    return data[sp + 1] == '/' ||
           (len >= sp + 8 && std::memcmp(data + sp + 1, "http://", 7) == 0);
}

long long parse_chunk_header(const char* data, size_t len, size_t& header_len) {
    header_len = 0;
    if (data == nullptr || len == 0) return -1;
    size_t crlf = std::string(data, len).find("\r\n");
    if (crlf == std::string::npos) {
        // A chunk-size line is a handful of bytes; a long one without CRLF is
        // garbage rather than a partial read.
        return len >= 64 ? -2 : -1;
    }
    std::string line(data, crlf);
    size_t semi = line.find(';');
    std::string size_text = trim_ws(semi == std::string::npos ? line : line.substr(0, semi));
    if (size_text.empty()) return -2;
    for (char c : size_text) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return -2;
    }
    errno = 0;
    char* endp = nullptr;
    unsigned long long v = std::strtoull(size_text.c_str(), &endp, 16);
    if (errno != 0 || endp == nullptr || *endp != '\0' || v > static_cast<unsigned long long>(LLONG_MAX))
        return -2;
    header_len = crlf + 2;
    return static_cast<long long>(v);
}

bool parse_ipv4(const std::string& text, uint32_t& network_order) {
    uint32_t parts[4];
    size_t start = 0;
    for (int i = 0; i < 4; ++i) {
        size_t sep = text.find('.', start);
        if (i < 3 && sep == std::string::npos) return false;
        if (i == 3 && sep != std::string::npos) return false;
        std::string comp = text.substr(start, i == 3 ? std::string::npos : sep - start);
        if (comp.empty() || comp.size() > 3 || !is_digits(comp)) return false;
        if (comp.size() > 1 && comp[0] == '0') return false;  // no octal-style leading zeros
        int v = std::atoi(comp.c_str());
        if (v < 0 || v > 255) return false;
        parts[i] = static_cast<uint32_t>(v);
        if (i < 3) start = sep + 1;
    }
    network_order = htonl((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]);
    return true;
}

std::string ipv4_to_string(uint32_t network_order) {
    uint32_t h = ntohl(network_order);
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", (h >> 24) & 0xff, (h >> 16) & 0xff,
                  (h >> 8) & 0xff, h & 0xff);
    return std::string(buf);
}

}  // namespace charles
