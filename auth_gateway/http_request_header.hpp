#ifndef NEOSYSTEM_HTTP_HTTP_REQUEST_HEADER_HPP_
#define NEOSYSTEM_HTTP_HTTP_REQUEST_HEADER_HPP_

#include <vector>
//#include <iostream>

#include <boost/asio.hpp>

#include "http_common.hpp"
#include "common.hpp"


namespace neosystem {
namespace http {

class http_request_header {
public:
	using cookie_map_type = std::unordered_map<std::string, std::string>;

	enum class result_type {
		good,
		bad,
		indeterminate
	};

private:
	enum class status_type {
		method_start,
		method,
		uri,
		http_version_h,
		http_version_t_1,
		http_version_t_2,
		http_version_p,
		http_version_slash,
		http_version_major_start,
		http_version_major,
		http_version_minor_start,
		http_version_minor,
		expecting_newline_1,
		header_line_start,
		header_lws,
		header_name,
		space_before_header_value,
		header_value,
		expecting_newline_2,
		expecting_newline_3
	};

	result_type consume(char);

private:
	std::size_t indeterminate_pos_;
	status_type state_;

	std::string request_method_str_;
	http_method_type request_method_;

	std::size_t content_length_;

	bool has_content_length_;

	bool keep_alive_;

	std::string version_str_;
	double version_;

	std::string host_;

	std::string request_path_;

	std::size_t header_size_;
	headers_type headers_;

	std::unordered_map<std::string, std::string> cookie_;

	std::string sec_websocket_key_;

	bool is_websocket_;

	bool is_http2_;
	std::string http2_settings_;

	void append_header(void) {
		++header_size_;
		header *p;
		if (headers_.size() < header_size_) {
			headers_.emplace_back();
			p = &(headers_.back());
		} else {
			p = &(headers_[header_size_ - 1]);
		}
		p->name = "";
		p->value = "";
		return;
	}

	header *header_back(void) {
		return &(headers_[header_size_ - 1]);
	}

	void append_name(char c) {
		header_back()->name.push_back(c);
		return;
	}

	void append_value(char c) {
		header_back()->value.push_back(c);
		return;
	}

public:
	http_request_header(void);
	void clear(void);

	template <typename InputIterator>
	std::tuple<result_type, InputIterator> parse(InputIterator begin2, InputIterator end) {
		auto it = begin2 + indeterminate_pos_;
		std::size_t count = 0;
		for (; it != end; ++it, ++count) {
			char input = *it;
			result_type result = result_type::indeterminate;

			switch (state_) {
			case status_type::method_start:
				if (!neosystem::util::is_char(input) || neosystem::util::is_ctl(input) || neosystem::util::is_tspecial(input)) {
					result = result_type::bad;
					break;
				}
				state_ = status_type::method;
				request_method_str_.push_back(input);
				break;
		
			case status_type::method:
				if (input == ' ') {
					state_ = status_type::uri;
					request_method_ = str_to_method(request_method_str_);
					break;
				} else if (!neosystem::util::is_char(input) || neosystem::util::is_ctl(input) || neosystem::util::is_tspecial(input)) {
					result = result_type::bad;
					break;
				}
				request_method_str_.push_back(input);
				break;
		
			case status_type::uri:
				if (input == ' ') {
					state_ = status_type::http_version_h;
					break;
				} else if (neosystem::util::is_ctl(input)) {
					result = result_type::bad;
					break;
				}
				request_path_.push_back(input);
				break;
		
			case status_type::http_version_h:
				if (input == 'H') {
					state_ = status_type::http_version_t_1;
					break;
				}
				result = result_type::bad;
				break;
		
			case status_type::http_version_t_1:
				if (input == 'T') {
					state_ = status_type::http_version_t_2;
					break;
				}
				result = result_type::bad;
				break;
		
			case status_type::http_version_t_2:
				if (input == 'T') {
					state_ = status_type::http_version_p;
					break;
				}
				result = result_type::bad;
				break;
		
			case status_type::http_version_p:
				if (input != 'P') {
					result = result_type::bad;
					break;
				}
				state_ = status_type::http_version_slash;
				break;
		
			case status_type::http_version_slash:
				if (input != '/') {
					result = result_type::bad;
					break;
				}
				state_ = status_type::http_version_major_start;
				version_str_.push_back(input);
				break;
		
			case status_type::http_version_major_start:
				if (!neosystem::util::is_digit(input)) {
					result = result_type::bad;
					break;
				}
				state_ = status_type::http_version_major;
				version_str_.push_back(input);
				break;
		
			case status_type::http_version_major:
				if (input == '.') {
					state_ = status_type::http_version_minor_start;
					version_str_.push_back(input);
					break;
				} else if (neosystem::util::is_digit(input)) {
					version_str_.push_back(input);
					break;
				}
				result = result_type::bad;
				break;
		
			case status_type::http_version_minor_start:
				if (!neosystem::util::is_digit(input)) {
					result = result_type::bad;
					break;
				}
				version_str_.push_back(input);
				state_ = status_type::http_version_minor;
				break;
		
			case status_type::http_version_minor:
				if (input == '\r') {
					state_ = status_type::expecting_newline_1;
					break;
				} else if (neosystem::util::is_digit(input)) {
					version_str_.push_back(input);
					break;
				}
				result = result_type::bad;
				break;
		
			case status_type::expecting_newline_1:
				if (input != '\n') {
					result = result_type::bad;
					break;
				}
				state_ = status_type::header_line_start;
				break;
		
			case status_type::header_line_start:
				if (input == '\r') {
					state_ = status_type::expecting_newline_3;
					break;
				} else if (header_size_ > 0 && (input == ' ' || input == '\t')) {
					state_ = status_type::header_lws;
					break;
				} else if (!neosystem::util::is_char(input) || neosystem::util::is_ctl(input) || neosystem::util::is_tspecial(input)) {
					result = result_type::bad;
					break;
				}
				append_header();
				append_name(input);
				state_ = status_type::header_name;
				break;
		
			case status_type::header_lws:
				if (input == '\r') {
					state_ = status_type::expecting_newline_2;
					break;
				} else if (input == ' ' || input == '\t') {
					break;
				} else if (neosystem::util::is_ctl(input)) {
					result = result_type::bad;
					break;
				}
				state_ = status_type::header_value;
				append_value(input);
				break;
		
			case status_type::header_name:
				if (input == ':') {
					state_ = status_type::space_before_header_value;
					break;
				} else if (!neosystem::util::is_char(input) || neosystem::util::is_ctl(input) || neosystem::util::is_tspecial(input)) {
					result = result_type::bad;
					break;
				}
				append_name(input);
				break;
		
			case status_type::space_before_header_value:
				if (input == ' ') {
					state_ = status_type::header_value;
					break;
				}
				result = result_type::bad;
				break;
		
			case status_type::header_value:
				if (input == '\r') {
					state_ = status_type::expecting_newline_2;
					auto *tmp = header_back();
					if (strcasecmp(tmp->name.c_str(), "Content-Length") == 0) {
						content_length_ = atoi(tmp->value.c_str());
					} else if (strcasecmp(tmp->name.c_str(), "Cookie") == 0) {
						parse_cookie(tmp->value, cookie_);
						//std::cout << "Cookie: " << tmp->value << std::endl;
						//for (auto cit = cookie_.begin(); cit != cookie_.end(); ++cit) {
						//	std::cout << "    " << cit->first << "=" << cit->second << std::endl;
						//}
					} else if (strcasecmp(tmp->name.c_str(), "Host") == 0) {
						host_ = tmp->value;
					} else if (strcasecmp(tmp->name.c_str(), "X-POPPO-ID") == 0) {
						result = result_type::bad;
						break;
					} else if (strcasecmp(tmp->name.c_str(), "Sec-WebSocket-Key") == 0) {
						sec_websocket_key_ = tmp->value;
					} else if (strcasecmp(tmp->name.c_str(), "Upgrade") == 0) {
						if (strcasecmp(tmp->value.c_str(), "websocket") == 0) {
							is_websocket_ = true;
						} else if (tmp->value == "h2c" || tmp->value == "h2") {
							is_http2_ = true;
						}
					} else if (strcasecmp(tmp->name.c_str(), "HTTP2-Settings") == 0) {
						http2_settings_ = tmp->value;
					}
					break;
				} else if (neosystem::util::is_ctl(input)) {
					result = result_type::bad;
					break;
				}
				append_value(input);
				break;
		
			case status_type::expecting_newline_2:
				if (input == '\n') {
					state_ = status_type::header_line_start;
					break;
				}
				result = result_type::bad;
				break;
		
			case status_type::expecting_newline_3:
				result = (input == '\n') ? result_type::good : result_type::bad;
				break;

			default:
				result = result_type::bad;
				break;
			}

			if (result == result_type::good || result == result_type::bad) {
				++it;
				return std::make_tuple(result, it);
			}
		}
		indeterminate_pos_ += count;
		return std::make_tuple(result_type::indeterminate, it);
	}

	http_method_type get_request_method(void) const { return request_method_; }
	const char *get_request_method_as_str(void) const { return method_to_str(request_method_); }

	std::size_t get_content_length(void) const { return content_length_; }

	bool get_has_content_length(void) const { return has_content_length_; }

	bool get_keep_alive(void) const { return keep_alive_; }

	double get_version(void) const { return version_; }

	const std::string& get_host(void) const { return host_; }

	const std::string& get_request_path(void) const { return request_path_; }

	const std::unordered_map<std::string, std::string>& get_cookie(void) const { return cookie_; }

	cookie_map_type::const_iterator find_cookie(const std::string& key) const {
		return cookie_.find(key);
	}

	bool exists_cookie(const std::string& key) const {
		const auto it = find_cookie(key);
		if (it == cookie_.end()) return false;
		return true;
	}

	const std::string& get_sec_websocket_key(void) const { return sec_websocket_key_; }

	bool is_websocket(void) const { return is_websocket_; }

	bool get_indeterminate_pos(void) const { return indeterminate_pos_; }

	bool is_http2(void) const { return is_http2_; }
	const std::string& get_http2_settings(void) const { return http2_settings_; }

	const std::string find_header(const std::string& header_name) const {
		for (const auto& header : headers_) {
			if (strcasecmp(header.name.c_str(), header_name.c_str()) == 0) {
				return header.value;
			}
		}
		return "";
	}

	bool is_http2_pri(void) const;

	const headers_type& get_headers(void) const { return headers_; }
};

}
}

#endif
