#ifndef NEOSYSTEM_HTTP2_HTTP2_STATIC_HEADERS_TABLE_HPP_
#define NEOSYSTEM_HTTP2_HTTP2_STATIC_HEADERS_TABLE_HPP_

#include "http_common.hpp"


namespace neosystem {
namespace http2 {

void init_http2_static_headers_table(void);
const neosystem::http::header *find_http2_static_headers_table(uint32_t);
std::size_t get_http2_static_headers_table_size(void);

}
}

#endif
