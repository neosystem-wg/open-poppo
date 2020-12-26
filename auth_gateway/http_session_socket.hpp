#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_HTTP_SESSION_SOCKET_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_HTTP_SESSION_SOCKET_HPP_

#include <boost/asio.hpp>


namespace poppo {
namespace auth_gateway {

class http_session_socket {
public:
	static constexpr const char *type_name = "http_session_socket";
	using socket_type = boost::asio::ip::tcp::socket;

private:
	boost::asio::io_context& io_context_;
	socket_type socket_;

public:
	http_session_socket(boost::asio::io_context& io_context) : io_context_(io_context), socket_(io_context) {
	}

	http_session_socket(boost::asio::io_context& io_context, boost::asio::ssl::context&) : io_context_(io_context), socket_(io_context) {
	}

	void socket_shutdown_receive(void) {
		boost::system::error_code ec;
		get_tcp_socket().shutdown(boost::asio::ip::tcp::socket::shutdown_receive, ec);
		return;
	}

	void socket_shutdown(void) {
		neosystem::util::socket_shutdown(socket_);
		return;
	}

	socket_type& get_socket(void) {
		return socket_;
	}

	boost::asio::ip::tcp::socket& get_tcp_socket(void) {
		return socket_;
	}

	bool is_open(void) {
		return socket_.is_open();
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

}
}

#endif
