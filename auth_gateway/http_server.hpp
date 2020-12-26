#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_HTTP_SERVER_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_HTTP_SERVER_HPP_

#include <iostream>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/shared_ptr.hpp>

#include "http_session.hpp"
#include "cache_holder.hpp"
#include "log.hpp"


namespace poppo {
namespace auth_gateway {

namespace http = neosystem::http;

int alpn_select_callback(SSL *, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *) {
	if (in == nullptr) {
		return SSL_TLSEXT_ERR_NOACK;
	}
	const auto& conf = application::get_config();
	if (conf.get_enable_http2() == false) {
		*out = (const unsigned char *) "http/1.1";
		*outlen = 8;
		return SSL_TLSEXT_ERR_OK;
	}
	unsigned int total = 0;
	for (const char *p = (const char *) in;  total < inlen; ) {
		int len = *p;
		if (strncmp(p + 1, "h2", len) == 0) {
			*out = (const unsigned char *) "h2";
			*outlen = 2;
			return SSL_TLSEXT_ERR_OK;
		}
		p += len + 1;
		total += len + 1;
	}
	*out = (const unsigned char *) "http/1.1";
	*outlen = 8;
	return SSL_TLSEXT_ERR_OK;
}

template<typename SocketType>
class http_server {
public:
	using socket_type = SocketType;

private:
	neosystem::wg::log::logger& logger_;
	const config& conf_;
	boost::asio::ssl::context ssl_context_;

	boost::asio::io_context& io_context_;
	boost::asio::ip::tcp::acceptor acceptor_v4_;
	boost::asio::ip::tcp::acceptor acceptor_;

	http_session<socket_type>::ptr_type session_for_v4_;
	http_session<socket_type>::ptr_type session_;

	http::handler_memory handler_memory_;
	cache_holder<socket_type>& holder_;
	object_cache<socket_type>& object_cache_;

	void async_accept_v4(void) {
		acceptor_v4_.async_accept(session_for_v4_->socket(), make_custom_alloc_handler(handler_memory_, [this](const boost::system::error_code& error) {
			if (error) {
				log::error(logger_)() << S_ << "accept error: " << error.message();
				return;
			}
			session_for_v4_->start();
			http_session<socket_type> *ptr = object_cache_.get_session();
			if (ptr == nullptr) {
				if constexpr (std::is_same<typename socket_type::socket_type, boost::asio::ip::tcp::socket>::value) {
					session_for_v4_ = http_session<socket_type>::create(io_context_, holder_);
				} else {
					session_for_v4_ = http_session<socket_type>::create(io_context_, holder_, ssl_context_);
				}
			} else {
				ptr->init();
				session_for_v4_ = typename http_session<socket_type>::ptr_type(ptr);
			}
			async_accept_v4();
			return;
		}));
		return;
	}

	void async_accept(void) {
		acceptor_.async_accept(session_->socket(), make_custom_alloc_handler(handler_memory_, [this](const boost::system::error_code& error) {
			if (error) {
				log::error(logger_)() << S_ << "accept error: " << error.message();
				return;
			}
			session_->start();
			http_session<socket_type> *ptr = object_cache_.get_session();
			if (ptr == nullptr) {
				if constexpr (std::is_same<typename socket_type::socket_type, boost::asio::ip::tcp::socket>::value) {
					session_ = http_session<socket_type>::create(io_context_, holder_);
				} else {
					session_ = http_session<socket_type>::create(io_context_, holder_, ssl_context_);
				}
			} else {
				ptr->init();
				session_ = typename http_session<socket_type>::ptr_type(ptr);
			}
			async_accept();
			return;
		}));
		return;
	}

public:
	http_server(cache_holder<socket_type>& holder, int v4, int v6, boost::asio::io_context& io_context)
		: logger_(application::get_logger()), conf_(application::get_config()), ssl_context_(boost::asio::ssl::context::tlsv12),
		io_context_(io_context), acceptor_v4_(io_context), acceptor_(io_context),
		holder_(holder), object_cache_(holder_.get_object_cache()) {

		if constexpr (std::is_same<typename socket_type::socket_type, boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>::value) {
			const auto& conf = application::get_config();
			ssl_context_.set_options(
				boost::asio::ssl::context::default_workarounds
				| boost::asio::ssl::context::no_sslv2
				| boost::asio::ssl::context::no_sslv3
				| boost::asio::ssl::context::no_tlsv1_1
				| boost::asio::ssl::context::single_dh_use);
			ssl_context_.use_certificate_chain_file(conf.get_cert_file());
			ssl_context_.use_private_key_file(conf.get_key_file(), boost::asio::ssl::context::pem);

			SSL_CTX_set_alpn_select_cb(ssl_context_.native_handle(), alpn_select_callback, nullptr);
		}
	
		acceptor_v4_.assign(boost::asio::ip::tcp::v4(), v4);
		acceptor_.assign(boost::asio::ip::tcp::v6(), v6);

		if constexpr (std::is_same<typename socket_type::socket_type, boost::asio::ip::tcp::socket>::value) {
			session_for_v4_ = http_session<socket_type>::create(io_context_, holder_);
			session_ = http_session<socket_type>::create(io_context_, holder_);
		} else {
			session_for_v4_ = http_session<socket_type>::create(io_context_, holder_, ssl_context_);
			session_ = http_session<socket_type>::create(io_context_, holder_, ssl_context_);
		}
		async_accept_v4();
	
		async_accept();
	}

	~http_server(void) {
		session_for_v4_.reset();
		session_.reset();
	
		acceptor_v4_.release();
		acceptor_.release();
	}
};

}
}

#endif
