#ifndef NEOSYSTEM_HTTP2_HTTP2_UTIL_HPP_
#define NEOSYSTEM_HTTP2_HTTP2_UTIL_HPP_

#include <ostream>
#include <cstdint>


namespace neosystem {
namespace http2 {

constexpr const uint32_t ERROR_CODE_PROTOCOL_ERROR = 0x1;
constexpr const uint32_t ERROR_CODE_FLOW_CONTROL_ERROR = 0x3;
constexpr const uint32_t ERROR_CODE_STREAM_CLOSED = 0x5;
constexpr const uint32_t ERROR_CODE_FRAME_SIZE_ERROR = 0x6;
constexpr const uint32_t ERROR_CODE_COMPRESSION_ERROR = 0x9;


uint64_t get_int(int, const uint8_t *, std::size_t, std::size_t&);
void write_http2_header(std::ostream&, const char *, const char *);
void write_http2_header2(std::ostream&, const std::string&, const std::string&);

}
}

#endif
