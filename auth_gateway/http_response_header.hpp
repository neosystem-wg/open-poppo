#ifndef NEOSYSTEM_HTTP_HTTP_RESPONSE_HEADER_HPP_
#define NEOSYSTEM_HTTP_HTTP_RESPONSE_HEADER_HPP_

#include <boost/asio.hpp>

#include "http_common.hpp"
#include "common.hpp"


namespace neosystem {
namespace http {

class http_response_header {
public:
	enum class result_type {
		good,
		bad,
		indeterminate
	};

private:
	enum class status_type {
		http_version_h,
		http_version_t_1,
		http_version_t_2,
		http_version_p,
		http_version_slash,
		http_version_major_start,
		http_version_major,
		http_version_minor_start,
		http_version_minor,
		status_code,
		message,
		expecting_newline_1,
		header_line_start,
		header_lws,
		header_name,
		space_before_header_value,
		header_value,
		expecting_newline_2,
		expecting_newline_3
	};

	std::size_t indeterminate_pos_;
	status_type state_;

	std::string version_str_;

	std::string status_code_str_;

	bool has_content_length_;
	std::size_t content_length_;

	bool is_chunked_;

	std::size_t header_size_;
	headers_type headers_;

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
	http_response_header(void);

	void clear(void);

	template <typename InputIterator>
	std::tuple<result_type, InputIterator> parse(InputIterator begin2, InputIterator end) {
		auto it = begin2 + indeterminate_pos_;
		std::size_t count = 0;
		for (; it != end; ++it, ++count) {
			char input = *it;
			result_type result = result_type::indeterminate;

			switch (state_) {
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
				if (input == ' ') {
					state_ = status_type::status_code;
					break;
				} else if (neosystem::util::is_digit(input)) {
					version_str_.push_back(input);
					break;
				}
				result = result_type::bad;
				break;
		
			case status_type::status_code:
				if (input == ' ') {
					if (!status_code_str_.empty()) {
						state_ = status_type::message;
					}
					break;
				}
				if (neosystem::util::is_digit(input) == false) {
					result = result_type::bad;
					break;
				}
				status_code_str_.push_back(input);
				break;
		
			case status_type::message:
				if (input == '\r') {
					state_ = status_type::expecting_newline_1;
					break;
				}
				if (neosystem::util::is_ctl(input)) {
					result = result_type::bad;
					break;
				}
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
						has_content_length_ = true;
						content_length_ = atoi(tmp->value.c_str());
					} else if (strcasecmp(tmp->name.c_str(), "Transfer-Encoding") == 0) {
						is_chunked_ = chunk_check(tmp->value);
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

	bool is_chunked(void) const { return is_chunked_; }

	const std::string& get_status_code_str(void) const { return status_code_str_; }
	bool get_has_content_length(void) const { return has_content_length_; }
	std::size_t get_content_length(void) const { return content_length_; }
	const headers_type& get_headers(void) const { return headers_; }
};

}
}

#endif
