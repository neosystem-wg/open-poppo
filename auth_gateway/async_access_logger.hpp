#ifndef POPPO_AUTH_GATEWAY_ASYNC_ACCESS_LOGGER_HPP_
#define POPPO_AUTH_GATEWAY_ASYNC_ACCESS_LOGGER_HPP_

#include <memory>
#include <chrono>

#include <boost/asio.hpp>
#include <boost/noncopyable.hpp>

#include "log.hpp"
#include "http_request_header.hpp"
#include "http2_request_header.hpp"
#include "config.hpp"
#include "application.hpp"


namespace poppo {
namespace auth_gateway {

namespace http = neosystem::http;
namespace http2 = neosystem::http2;

class log_object {
public:
	using self_type = log_object;
	using ptr_type = std::shared_ptr<self_type>;

private:
	std::chrono::system_clock::time_point start_;
	std::chrono::system_clock::time_point complete_;

	std::string method_;

	std::string request_path_;

	std::string user_agent_;

	std::string http_status_;

	template<typename HeaderType>
	void init(const HeaderType& header) {
		method_ = header.get_request_method_as_str();
		request_path_ = header.get_request_path();
		user_agent_ = header.find_header("User-Agent");
		return;
	}

public:
	log_object(const http::http_request_header& header) {
		init(header);
	}

	log_object(const http2::http2_request_header& header) {
		init(header);
	}

	static ptr_type create(const http::http_request_header& header) {
		return std::make_shared<self_type>(header);
	}

	static ptr_type create(const http2::http2_request_header& header) {
		return std::make_shared<self_type>(header);
	}

	const std::string& get_request_path(void) const { return request_path_; }

	void set_http_status(const char *http_status) {
		http_status_ = http_status;
		return;
	}

	void set_request_start_time(void) {
		start_ = std::chrono::system_clock::now();
		return;
	}

	void set_request_complete_time(void) {
		complete_ = std::chrono::system_clock::now();
		return;
	}

	void to_string(std::string& str) {
		std::stringstream stream;
		stream << method_ << " " << request_path_ << " " << user_agent_ << " "
			<< std::chrono::duration_cast<std::chrono::milliseconds>(complete_ - start_).count() << " " << http_status_;
		str = stream.str();
		return;
	}
};


class async_access_logger : private boost::noncopyable {
private:
	boost::asio::io_context io_context_;

	neosystem::wg::log::logger& logger_;

public:
	async_access_logger(void) : logger_(application::get_logger()) {
	}

	void run(void) {
		boost::asio::signal_set signals(io_context_, SIGINT, SIGTERM);
		signals.async_wait([this](const boost::system::error_code&, int) {
			io_context_.stop();
			return;
		});
		io_context_.run();
		return;
	}

	void dump(const log_object::ptr_type& log_obj) {
		if (log_obj == nullptr) {
			neosystem::wg::log::info(logger_)() << "log_obj is nullptr";
			return;
		}
		boost::asio::post(io_context_, [this, log_obj] {
			std::string str;
			log_obj->to_string(str);
			neosystem::wg::log::info(logger_)() << str;
			return;
		});
		return;
	}
};

}
}

#endif
