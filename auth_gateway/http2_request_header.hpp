#ifndef NEOSYSTEM_HTTP2_HTTP2_REQUEST_HEADER_HPP_
#define NEOSYSTEM_HTTP2_HTTP2_REQUEST_HEADER_HPP_

#include <iostream>

#include "http_common.hpp"
#include "http2_dynamic_headers_table.hpp"
#include "http2_util.hpp"
#include "http2_huffman.hpp"
#include "common.hpp"


namespace neosystem {
namespace http2 {

namespace http = neosystem::http;

class http2_request_header {
public:
	using cookie_map_type = std::unordered_map<std::string, std::string>;

private:
	std::string authority_;
	std::string method_;
	std::string scheme_;
	std::string path_;

	http::headers_type headers_;
	cookie_map_type cookie_;

	std::size_t content_length_;

	bool is_update_dynamic_header_table_size(uint8_t v) {
		return (v & 0b11100000) == 0b00100000;
	}

	bool is_index_header(uint8_t v) {
		return v & 0b10000000;
	}

	bool is_update_index_header(uint8_t v) {
		return (v & 0b11000000) == 0b01000000;
	}

	bool is_no_update_index_header(uint8_t v) {
		return (v & 0b11110000) == 0b00000000;
	}

	bool is_no_index_header(uint8_t v) {
		return (v & 0b11110000) == 0b00010000;
	}

	bool is_huffman(uint8_t v) {
		return v & 0b10000000;
	}

	void append_cookie(http::header& h, const std::string& value) {
		if (h.value != "") {
			h.value += "; ";
		}
		h.value += value;
		http::parse_cookie(value, cookie_);
		return;
	}

	bool move_header(http::header& cookie_header, const http::header& h) {
		if (h.name == "cookie") {
			append_cookie(cookie_header, h.value);
		} else if (h.name == ":authority") {
			authority_ = std::move(h.value);
		} else if (h.name == ":method") {
			if (method_ != "") {
				return false;
			}
			method_ = std::move(h.value);
		} else if (h.name == ":scheme") {
			if (scheme_ != "") {
				return false;
			}
			scheme_ = std::move(h.value);
		} else if (h.name == ":path") {
			if (path_ != "") {
				return false;
			}
			path_ = std::move(h.value);
		} else if (h.name == "host" && authority_ == "") {
			authority_ = std::move(h.value);
		} else if (strcasecmp(h.name.c_str(), "X-POPPO-ID") == 0) {
			return true;
		} else {
			if (h.name == "content-length") {
				content_length_ = atoi(h.value.c_str());
			}
			headers_.emplace(headers_.end(), std::move(h.name), std::move(h.value));
		}
		return true;
	}

	bool is_valid_header(bool& allow_pseudo_header, const http::header& h) {
		if (allow_pseudo_header) {
			if (h.name[0] != ':') {
				allow_pseudo_header = false;
			}
		} else {
			if (h.name[0] == ':') {
				return false;
			}
			if (h.name == "te" && h.value != "trailers") {
				return false;
			}
		}
		return true;
	}

	bool is_valid_header(const http::header& h) {
		for (char c : h.name) {
			if (isupper(c) != 0) {
				return false;
			}
		}
		if (h.name[0] == ':') {
			if (h.name != ":authority" && h.name != ":method" && h.name != ":scheme" && h.name != ":path") {
				return false;
			}
		} else {
			if (h.name == "connection") {
				return false;
			}
			if (h.name == "te" && h.value != "trailers") {
				return false;
			}
		}
		return true;
	}

	bool set_header(http::header& cookie_header, const http::header& h) {
		if (h.name == "cookie") {
			append_cookie(cookie_header, h.value);
		} else if (h.name == ":authority") {
			authority_ = h.value;
		} else if (h.name == ":method") {
			if (method_ != "") {
				return false;
			}
			method_ = h.value;
		} else if (h.name == ":scheme") {
			if (scheme_ != "") {
				return false;
			}
			scheme_ = h.value;
		} else if (h.name == ":path") {
			if (path_ != "") {
				return false;
			}
			path_ = h.value;
		} else if (h.name == "host" && authority_ == "") {
			authority_ = h.value;
		} else if (strcasecmp(h.name.c_str(), "X-POPPO-ID") == 0) {
			return true;
		} else {
			if (h.name == "content-length") {
				content_length_ = atoi(h.value.c_str());
			}
			headers_.push_back(h);
		}
		return true;
	}

public:
	http2_request_header(void) : content_length_(0) {
	}

	uint32_t parse(const uint8_t *p, const std::size_t length, http2_dynamic_headers_table& table, uint32_t settings_header_table_size) {
		std::size_t consume_length;
		const http::header *header_ptr;
		std::size_t remain = length;
		http::header cookie_header = {"cookie", ""};
		bool dynamic_table_size_update = false;
		bool allow_pseudo_header = true;

		content_length_ = 0;

		for (std::size_t i = 0; i < length; ) {
			dynamic_table_size_update = false;
			bool need_update_table = false;
			if (is_index_header(*p)) {
				uint64_t index = get_int(7, p, remain, consume_length);
				header_ptr = table.get((uint32_t) index);
				if (header_ptr == nullptr) {
					std::cerr << S_ << "unexpected header(1)" << std::endl;
					return ERROR_CODE_COMPRESSION_ERROR;
				}
				if (header_ptr->name == ":status") {
					return ERROR_CODE_PROTOCOL_ERROR;
				}
				if (is_valid_header(allow_pseudo_header, *header_ptr) == false) {
					return ERROR_CODE_PROTOCOL_ERROR;
				}
				if (set_header(cookie_header, *header_ptr) == false) {
					return ERROR_CODE_PROTOCOL_ERROR;
				}

				i += consume_length;
				p += consume_length;
				remain -= consume_length;
				continue;
			}
			
			uint64_t index = 0;
			if (is_update_index_header(*p)) {
				need_update_table = true;

				index = get_int(6, p, remain, consume_length);
				i += consume_length;
				p += consume_length;
				remain -= consume_length;
			} else if (is_no_update_index_header(*p)) {
				need_update_table = false;

				index = get_int(4, p, remain, consume_length);
				i += consume_length;
				p += consume_length;
				remain -= consume_length;
			} else if (is_no_index_header(*p)) {
				need_update_table = false;

				index = get_int(4, p, remain, consume_length);
				i += consume_length;
				p += consume_length;
				remain -= consume_length;
			} else if (is_update_dynamic_header_table_size(*p)) {
				uint64_t new_size = get_int(5, p, remain, consume_length);
				if (new_size > settings_header_table_size) {
					std::cerr << S_ << "Invalid header table size: " << new_size << ", " << settings_header_table_size << std::endl;
					return ERROR_CODE_COMPRESSION_ERROR;
				}
				table.set_limit((std::size_t) new_size);
				i += consume_length;
				p += consume_length;
				remain -= consume_length;
				dynamic_table_size_update = true;
				continue;
			} else {
				std::cerr << S_ << "unexpected type" << std::endl;
				return ERROR_CODE_PROTOCOL_ERROR;
			}
			if (i > length || remain <= 0) {
				std::cerr << S_ << "unexpected header (i: " << i << ", remain: " << remain << ")" << std::endl;
				return ERROR_CODE_COMPRESSION_ERROR;
			}

			if (index != 0) {
				header_ptr = table.get((uint32_t) index);
				if (header_ptr == nullptr) {
					std::cerr << S_ << "unexpected header(2)" << std::endl;
					return ERROR_CODE_COMPRESSION_ERROR;
				}
				http::header h = *header_ptr;

				bool huffman = is_huffman(*p);
				uint64_t str_length = get_int(7, p, remain, consume_length);
				i += consume_length;
				if (i + str_length > length) {
					std::cerr << S_ << "error (i: " << i << ", str_length: " << str_length << ", length: " << length << ")" << std::endl;
					return ERROR_CODE_COMPRESSION_ERROR;
				}
				p += consume_length;
				remain -= consume_length;

				if (huffman) {
					if (decode_huffman(str_length, p, h.value) == false) {
						std::cerr << S_ << "decode error (1)" << std::endl;
						return ERROR_CODE_COMPRESSION_ERROR;
					}
				} else {
					h.value = std::string((const char *) p, str_length);
				}
				i += str_length;
				p += str_length;
				remain -= str_length;

				if (is_valid_header(h) == false) {
					return ERROR_CODE_PROTOCOL_ERROR;
				}
				if (is_valid_header(allow_pseudo_header, h) == false) {
					return ERROR_CODE_PROTOCOL_ERROR;
				}
				if (need_update_table) {
					table.add(h);
				}
				if (move_header(cookie_header, h) == false) {
					return ERROR_CODE_PROTOCOL_ERROR;
				}
			} else {
				bool huffman = is_huffman(*p);
				uint64_t str_length = get_int(7, p, remain, consume_length);
				if (i + str_length > length) {
					std::cerr << S_ << "error" << std::endl;
					return ERROR_CODE_COMPRESSION_ERROR;
				}
				i += consume_length;
				p += consume_length;
				remain -= consume_length;
				http::header h;
				if (huffman) {
					if (decode_huffman(str_length, p, h.name) == false) {
						std::cerr << S_ << "decode error (2)" << std::endl;
						return ERROR_CODE_COMPRESSION_ERROR;
					}
				} else {
					h.name = std::string((const char *) p, str_length);
				}
				i += str_length;
				p += str_length;
				remain -= str_length;

				huffman = is_huffman(*p);
				str_length = get_int(7, p, remain, consume_length);
				if (i + str_length > length) {
					std::cerr << S_ << "error" << std::endl;
					return ERROR_CODE_COMPRESSION_ERROR;
				}
				i += consume_length;
				p += consume_length;
				remain -= consume_length;
				if (huffman) {
					if (decode_huffman(str_length, p, h.value) == false) {
						std::cerr << S_ << "decode error (3)" << std::endl;
						return ERROR_CODE_COMPRESSION_ERROR;
					}
				} else {
					h.value = std::string((const char *) p, str_length);
				}
				i += str_length;
				p += str_length;
				remain -= str_length;

				if (is_valid_header(h) == false) {
					return ERROR_CODE_PROTOCOL_ERROR;
				}
				if (is_valid_header(allow_pseudo_header, h) == false) {
					return ERROR_CODE_PROTOCOL_ERROR;
				}
				if (need_update_table) {
					table.add(h);
				}
				if (move_header(cookie_header, h) == false) {
					return ERROR_CODE_PROTOCOL_ERROR;
				}
			}
		}
		if (cookie_header.value != "") {
			headers_.push_back(cookie_header);
		}
		if (dynamic_table_size_update) {
			std::cerr << S_ << "error" << std::endl;
			return ERROR_CODE_COMPRESSION_ERROR;
		}
		if (path_ == "" || method_ == "" || scheme_ == "") {
			return ERROR_CODE_PROTOCOL_ERROR;
		}
		return 0;
	}

	const http::headers_type& get_headers(void) const { return headers_; }
	const char *get_request_method_as_str(void) const { return method_.c_str(); }
	http::http_method_type get_request_method(void) const { return http::str_to_method(method_); }
	const std::string& get_request_path(void) const { return path_; }
	const std::string& get_host(void) const { return authority_; }

	cookie_map_type::const_iterator find_cookie(const std::string& key) const {
		return cookie_.find(key);
	}

	bool exists_cookie(const std::string& key) const {
		const auto it = find_cookie(key);
		if (it == cookie_.end()) return false;
		return true;
	}

	const std::string find_header(const std::string& header_name) const {
		for (const auto& header : headers_) {
			if (strcasecmp(header.name.c_str(), header_name.c_str()) == 0) {
				return header.value;
			}
		}
		return "";
	}

	std::size_t get_content_length(void) const { return content_length_; }
};

}
}

#endif
