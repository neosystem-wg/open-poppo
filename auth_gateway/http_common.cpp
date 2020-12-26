#include <sys/socket.h>

#include <random>

#include <boost/thread.hpp>

#include "http_common.hpp"
#include "common.hpp"


namespace neosystem {
namespace http {

namespace util = neosystem::util;

static constexpr const char *HTTP = "http://";
static constexpr const char *HTTPS = "https://";

enum class status_type {
	status_host,
	status_port,
	status_path,
	status_param,
};

bool chunk_check(const std::string& str) {
	return str.find("chunked") != std::string::npos;
}

void set_tcp_option(boost::asio::ip::tcp::socket& socket) {
	socket.set_option(boost::asio::ip::tcp::no_delay(true));

	int on = 1;
	int fd = socket.native_handle();
	setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &on, sizeof(int));

	//int on = 1;
	//int fd = socket.native_handle();
	//setsockopt(fd, IPPROTO_TCP, TCP_CORK, &on, sizeof(on));
	return;
}


bool url_info::init(const std::string& url) {
	if (strncmp(HTTP, url.c_str(), strlen(HTTP)) == 0) {
		is_ssl_ = false;
		return init(url, strlen(HTTP));
	} else if (strncmp(HTTPS, url.c_str(), strlen(HTTPS)) == 0) {
		is_ssl_ = true;
		return init(url, strlen(HTTPS));
	}
	return false;
}

bool url_info::init(const std::string& url, int offset) {
	if (url.size() <= (std::size_t) offset) return false;
	status_type status = status_type::status_host;
	path_ = "/";
	for (auto it = url.begin() + offset, end = url.end(); it != end; ++it) {
		char input = *it;
		switch (status) {
		case status_type::status_host:
			if (input == '/') {
				status = status_type::status_path;
				break;
			} else if (input == ':') {
				status = status_type::status_port;
				break;
			}
			host_ += input;
			break;
		case status_type::status_port:
			if (input == '/') {
				status = status_type::status_path;
				if (port_.empty()) return false;
				break;
			} else if (!neosystem::util::is_digit(input)) {
				return false;
			}
			port_ += input;
			break;
		case status_type::status_path:
			if (input == '?') {
				status = status_type::status_param;
				break;
			}
			path_ += input;
			break;
		case status_type::status_param:
			param_ += input;
			break;
		}
	}

	if (host_.empty()) return false;
	if (port_.empty()) port_ = (is_ssl_) ? "443" : "80";
	return true;
}

std::string trim_space(const std::string& s) {
	size_t beg = s.find_first_not_of(" \r\n\t");
	return (beg == std::string::npos) ? "" : s.substr(beg, s.find_last_not_of(" \r\n\t") - beg + 1);
}

void parse_cookie(const std::string& src, std::unordered_map<std::string, std::string>& result) {
	std::string key, value;
	std::string *t = &key;

	for (auto it = src.begin(), end = src.end(); it != end; ++it) {
		if (*it == ';') {
			if (!key.empty()) {
				result[trim_space(key)] = trim_space(value);
			}
			key.clear();
			value.clear();
			t = &key;
		} else if (*it == '=') {
			if (t == &value) {
				t->push_back(*it);
			} else {
				t = &value;
			}
		} else {
			t->push_back(*it);
		}
	}
	if (!key.empty()) {
		result[trim_space(key)] = trim_space(value);
	}
	return;
}

void remove_get_parameter(const std::string& src, std::string& result) {
	for (auto it = src.begin(), end = src.end(); it != end; ++it) {
		if (*it == '?') break;
		result.push_back(*it);
	}
	return;
}

void parse_http_url(const std::string& src, std::unordered_map<std::string, std::string>& result) {
	for (auto it = src.begin(), end = src.end(); it != end; ++it) {
		if (*it == '?') {
			++it;
			if (it == end) break;
			parse_http_post(it, end, result);
			break;
		}
	}
	return;
}

void parse_http_post(const std::string::const_iterator begin, const std::string::const_iterator end, std::unordered_map<std::string, std::string>& result) {
	std::string key, value;
	std::string *t = &key;

	for (auto it = begin; it != end; ++it) {
		if (*it == '&') {
			if (!key.empty()) result[key] = value;
			key.clear();
			value.clear();
			t = &key;
		} else if (*it == '=') {
			if (t == &value) {
				t->push_back(*it);
			} else {
				t = &value;
			}
		} else {
			t->push_back(*it);
		}
	}
	if (!key.empty()) {
		result[key] = value;
	}
	return;
}

void parse_http_post(const std::string& src, std::unordered_map<std::string, std::string>& result) {
	std::string key, value;
	std::string *t = &key;

	for (auto it = src.begin(), end = src.end(); it != end; ++it) {
		if (*it == '&') {
			if (!key.empty()) result[key] = value;
			key.clear();
			value.clear();
			t = &key;
		} else if (*it == '=') {
			if (t == &value) {
				t->push_back(*it);
			} else {
				t = &value;
			}
		} else {
			t->push_back(*it);
		}
	}
	if (!key.empty()) {
		result[key] = value;
	}
	return;
}

bool generate_session_id(std::string& session_id) {
	try {
		std::random_device rd;
		std::mt19937 mt(rd());

		auto p = std::chrono::system_clock::now();
		auto e = std::chrono::duration_cast<std::chrono::milliseconds>(p.time_since_epoch());

		std::stringstream s;
		s << mt() << boost::this_thread::get_id() << e.count();
		session_id = util::get_sha1_hash(s.str());
	} catch (...) {
		return false;
	}
	return true;
}

headers_type::const_iterator find_header(const header& target, const headers_type& headers) {
	for (auto it = headers.begin(); it != headers.end(); ++it) {
		if (strcasecmp(it->name.c_str(), target.name.c_str()) == 0) return it;
	}
	return headers.end();
}

void merge_headers(headers_type& result, const headers_type& src1, const headers_type& src2) {
	headers_type src3(src2);
	for (const auto& h : src1) {
		auto it = find_header(h, src3);
		if (it != src3.end()) {
			// src3の内容を追加
			result.push_back(*it);
			src3.erase(it);
		} else {
			// src1の内容を追加
			result.push_back(h);
		}
	}
	for (const auto& h : src3) {
		result.push_back(h);
	}
	return;
}

void replace_path(const std::string& config_request_path, const std::string& config_path,
		const std::string& request_path, std::string& new_request_path) {
	new_request_path = config_path;
	if (config_path[config_path.size() - 1] != '/') {
		new_request_path += '/';
	}

	new_request_path += (request_path.c_str() + config_request_path.size());
	return;
}

const char *to_day_name(const struct tm& t) {
	switch (t.tm_wday) {
	case 0:
		return "Sun";
	case 1:
		return "Mon";
	case 2:
		return "Tue";
	case 3:
		return "Wed";
	case 4:
		return "Thu";
	case 5:
		return "Fri";
	case 6:
		return "Sat";
	}
	return "";
}

const char *to_month(const struct tm& t) {
	switch (t.tm_mon) {
	case 0:
		return "Jan";
	case 1:
		return "Feb";
	case 2:
		return "Mar";
	case 3:
		return "Apr";
	case 4:
		return "May";
	case 5:
		return "Jun";
	case 6:
		return "Jul";
	case 7:
		return "Aug";
	case 8:
		return "Sep";
	case 9:
		return "Oct";
	case 10:
		return "Nov";
	case 11:
		return "Dec";
	}
	return "";
}

const char *method_to_str(http_method_type type) {
	switch (type) {
	case http_method_type::GET:
		return "GET";
	case http_method_type::HEAD:
		return "HEAD";
	case http_method_type::POST:
		return "POST";
	case http_method_type::PUT:
		return "PUT";
	case http_method_type::DELETE:
		return "DELETE";
	case http_method_type::OPTIONS:
		return "OPTIONS";
	case http_method_type::TRACE:
		return "TRACE";
	case http_method_type::CONNECT:
		return "CONNECT";
	case http_method_type::PATCH:
		return "PATCH";
	case http_method_type::UNKNOWN:
		break;
	}
	return "";
}

http_method_type str_to_method(const std::string& str) {
	if (str == "GET") {
		return http_method_type::GET;
	} else if (str == "HEAD") {
		return http_method_type::HEAD;
	} else if (str == "POST") {
		return http_method_type::POST;
	} else if (str == "PUT") {
		return http_method_type::PUT;
	} else if (str == "DELETE") {
		return http_method_type::DELETE;
	} else if (str == "OPTIONS") {
		return http_method_type::OPTIONS;
	} else if (str == "TRACE") {
		return http_method_type::TRACE;
	} else if (str == "CONNECT") {
		return http_method_type::CONNECT;
	} else if (str == "PATCH") {
		return http_method_type::PATCH;
	}
	return http_method_type::UNKNOWN;
}

}
}
