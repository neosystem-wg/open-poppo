#include <string>

#include "http_request_header.hpp"


namespace neosystem {
namespace http {

http_request_header::http_request_header(void) {
	clear();
}

void http_request_header::clear(void) {
	indeterminate_pos_ = 0;
	state_ = status_type::method_start;
	request_method_str_.clear();
	content_length_ = 0;
	has_content_length_ = false;
	keep_alive_ = false;
	version_str_.clear();
	host_.clear();
	request_path_.clear();
	header_size_ = 0;
	is_websocket_ = false;
	cookie_.clear();
	headers_.clear();
	sec_websocket_key_.clear();
	return;
}

bool http_request_header::is_http2_pri(void) const {
	if (request_method_str_ != "PRI") {
		return false;
	}
	if (request_path_ != "*") {
		return false;
	}
	if (version_str_ != "/2.0") {
		return false;
	}
	return true;
}

}
}
