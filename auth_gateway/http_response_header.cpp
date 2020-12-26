#include <iostream>
#include <string>

#include <boost/spirit/include/phoenix.hpp>
#include <boost/spirit/include/qi.hpp>
#include <boost/spirit/include/qi_string.hpp>
#include <boost/lexical_cast.hpp>

#include "http_response_header.hpp"


namespace neosystem {
namespace http {

http_response_header::http_response_header(void) {
	clear();
}

void http_response_header::clear(void) {
	indeterminate_pos_ = 0;
	state_ = status_type::http_version_h;
	version_str_.clear();
	status_code_str_.clear();
	has_content_length_ = false;
	content_length_ = 0;
	is_chunked_ = false;
	header_size_ = 0;
	headers_.clear();
	return;
}

}
}
