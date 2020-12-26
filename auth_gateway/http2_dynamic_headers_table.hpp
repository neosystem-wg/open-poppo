#ifndef NEOSYSTEM_HTTP2_HTTP2_DYNAMIC_HEADERS_TABLE_HPP_
#define NEOSYSTEM_HTTP2_HTTP2_DYNAMIC_HEADERS_TABLE_HPP_

#include "http2_static_headers_table.hpp"
#include "http_common.hpp"


namespace neosystem {
namespace http2 {

namespace http = neosystem::http;

class http2_dynamic_headers_table {
private:
	std::size_t limit_;

	http::headers_type headers_;

public:
	http2_dynamic_headers_table(void) {
	}

	void set_limit(std::size_t limit) {
		limit_ = limit;
		return;
	}

	void add(const http::header& h) {
		headers_.insert(headers_.begin(), h);
		return;
	}

	void add(const http::headers_type& h) {
		headers_.insert(headers_.begin(), h.begin(), h.end());
		return;
	}

	const http::header *get(uint32_t index) {
		if (index < 1) {
			return nullptr;
		}
		const http::header *p = neosystem::http2::find_http2_static_headers_table(index);
		if (p != nullptr) {
			return p;
		}

		index -= (uint32_t) neosystem::http2::get_http2_static_headers_table_size();
		--index;
		if (index < headers_.size()) {
			return &headers_[index];
		}
		return nullptr;
	}
};

}
}

#endif
