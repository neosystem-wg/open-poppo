#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_HTTPS_SESSION_SOCKET_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_HTTPS_SESSION_SOCKET_HPP_

#include <boost/asio.hpp>

#include "application.hpp"


namespace poppo {
namespace auth_gateway {

class https_session_socket {
public:
	static constexpr const char *type_name = "https_session_socket";
	using socket_type = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;

private:
	boost::asio::io_context& io_context_;
	boost::asio::ssl::context& ssl_context_;

	std::unique_ptr<socket_type> socket_;

public:
	https_session_socket(boost::asio::io_context& io_context, boost::asio::ssl::context& ssl_context) :
		io_context_(io_context), ssl_context_(ssl_context), socket_(std::make_unique<socket_type>(io_context, ssl_context)) {
	}

	void socket_shutdown_receive(void) {
		boost::system::error_code ec;
		get_tcp_socket().shutdown(boost::asio::ip::tcp::socket::shutdown_receive, ec);
		return;
	}

	void socket_shutdown(void) {
		if (socket_ == nullptr) return;
		boost::system::error_code ec;
		socket_->shutdown(ec);
		socket_->lowest_layer().close(ec);
		socket_.reset();
		return;
	}

	socket_type& get_socket(void) {
		if (socket_ == nullptr) {
			socket_ = std::make_unique<socket_type>(io_context_, ssl_context_);
		}
		return *socket_;
	}

	boost::asio::ip::tcp::socket& get_tcp_socket(void) {
		if (socket_ == nullptr) {
			socket_ = std::make_unique<socket_type>(io_context_, ssl_context_);
		}
		auto& s = socket_->lowest_layer();
		return *((boost::asio::ip::tcp::socket *) &s);
	}

	bool is_open(void) {
		return get_tcp_socket().is_open();
	}

	boost::asio::io_context& get_io_context(void) {
		return io_context_;
	}

	void get_remote_endpoint(std::string& str) {
		boost::system::error_code ec;
		auto endpoint = get_tcp_socket().remote_endpoint(ec);
		if (ec) {
			return;
		}
		str = endpoint.address().to_string();
		return;
	}
};


namespace traits {

template<typename T>
struct is_https {
	static constexpr bool value = false;
};

template<>
struct is_https<https_session_socket> {
	static constexpr bool value = true;
};

}

}
}

#endif
