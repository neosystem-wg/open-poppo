#include <iostream>
#include <thread>
#include <functional>

#include <boost/asio.hpp>
#include <boost/ref.hpp>
#include <boost/asio/ssl.hpp>

#include "application.hpp"
#include "http_server.hpp"
#include "cache_holder.hpp"
#include "session_manager.hpp"
#include "https_session_socket.hpp"
#include "http2_static_headers_table.hpp"
#include "http2_huffman.hpp"
#include "async_access_logger.hpp"

#define VERSION "0.0.1"


namespace poppo {
namespace auth_gateway {

using namespace neosystem::wg;

volatile bool application::stop_flag_;     //!< 実行停止フラグ
log::logger application::logger_;
config application::conf_;
std::unique_ptr<session_manager> application::session_;
std::unique_ptr<async_access_logger> application::access_logger_;


class acceptors : private boost::noncopyable {
private:
	boost::asio::ip::tcp::acceptor acceptor_v4_;
	boost::asio::ip::tcp::acceptor acceptor_v6_;

	void init_v4(boost::asio::ip::tcp::acceptor& acceptor, short port, int backlog) {
		auto endpoint = boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port);
		acceptor.open(endpoint.protocol());
	
		set_acceptor_option(acceptor);
	
		acceptor.bind(endpoint);
		acceptor.listen(backlog);
		return;
	}

	void init_v6(boost::asio::ip::tcp::acceptor& acceptor, short port, int backlog) {
		auto endpoint = boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v6(), port);
		acceptor.open(endpoint.protocol());
	
		set_acceptor_option(acceptor);

		int fd = acceptor.native_handle();
		int on = 1;
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
	
		acceptor.bind(endpoint);
		acceptor.listen(backlog);
		return;
	}

	void set_acceptor_option(boost::asio::ip::tcp::acceptor& acceptor) {
		acceptor.set_option(boost::asio::ip::tcp::no_delay(true));
	
		//boost::asio::socket_base::linger option(true, 0);
		//acceptor.set_option(option);
	
		//set_receive_buffer_size(acceptor, 256 * 1000);
		//set_send_buffer_size(acceptor, 256 * 1000);
	
		int fd = acceptor.native_handle();
		int on = 1;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
		//setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
		setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &on, sizeof(on));
		//setsockopt(fd, IPPROTO_TCP, TCP_CORK, &on, sizeof(on));
		return;
	}

public:
	acceptors(boost::asio::io_context& context, short port, int backlog)
		: acceptor_v4_(context), acceptor_v6_(context) {
		if (port > 0) {
			init_v4(acceptor_v4_, port, backlog);
			init_v6(acceptor_v6_, port, backlog);
		}
	}

	int v4_native_handle(void) {
		return acceptor_v4_.native_handle();
	}

	int v6_native_handle(void) {
		return acceptor_v6_.native_handle();
	}
};


template<typename SocketType>
class server_wrapper : private boost::noncopyable {
public:
	using socket_type = SocketType;

private:
	cache_holder<socket_type> cache_;
	http_server<socket_type> server_;

public:
	server_wrapper(std::size_t cache_size, std::size_t streambuf_cache_size, acceptors& a, boost::asio::io_context& context) :
		cache_(cache_size, streambuf_cache_size),
		server_(cache_, a.v4_native_handle(), a.v6_native_handle(), context) {
	}

	~server_wrapper(void) {
		cache_.get_object_cache().shutdown();
	}
};


/**
 * applicationの実装クラス
 * */
class application_impl {
private:
	log::logger& logger_;
	boost::asio::io_context io_context_;

	boost::asio::io_context timer_io_context_;
	boost::asio::steady_timer timer_;

	void handle_timeout(void) {
		timer_.expires_from_now(std::chrono::minutes(1));
		auto func = [this](const boost::system::error_code& ec) {
			if (ec) return;
			auto& p = application::get_session();
			p.remove_timeout_session();
			handle_timeout();
			return;
		};
		timer_.async_wait(func);
		return;
	}

public:
	application_impl(void) : logger_(application::get_logger()), io_context_(BOOST_ASIO_CONCURRENCY_HINT_UNSAFE), timer_(timer_io_context_) {
	}

	int run(void) {
		try {
			int thread_count = std::thread::hardware_concurrency();
			if (thread_count == 0) thread_count = 1;
			log::info(logger_)() << "application start  (" VERSION ")  thread count: " << thread_count;

			const config& c = application::get_config();

			acceptors http(io_context_, c.get_port(), c.get_backlog());
			acceptors https(io_context_, c.get_ssl_port(), c.get_backlog());

			// invoke thread
			std::vector<std::unique_ptr<std::thread>> threads;
			for (int i = 0; i < thread_count; ++i) {
				auto p = std::make_unique<std::thread>([&http, &https] {
					boost::asio::io_context context(1);
					const config& conf = application::get_config();

					std::unique_ptr<server_wrapper<http_session_socket>> server = std::make_unique<server_wrapper<http_session_socket>>(
						conf.get_cache_size(), conf.get_streambuf_cache_size(), http, context
						);
					std::unique_ptr<server_wrapper<https_session_socket>> https_server;
					if (conf.get_ssl_port() > 0) {
						https_server = std::make_unique<server_wrapper<https_session_socket>>(
							conf.get_cache_size(), conf.get_streambuf_cache_size(), https, context
							);
					}

					boost::asio::signal_set signals(context, SIGINT, SIGTERM);
					signals.async_wait([&context] (const boost::system::error_code&, int) {
						context.stop();
					});

					context.run();
					return;
				});
				threads.push_back(std::move(p));
			}

			boost::asio::signal_set signals(timer_io_context_, SIGINT, SIGTERM);
			handle_timeout();
			signals.async_wait([this](const boost::system::error_code&, int) {
				timer_io_context_.stop();
			});
			timer_io_context_.run();

			// join
			for (int i = 0; i < thread_count; ++i) {
				threads[i]->join();
			}

			log::info(logger_)() << "application exit.";
		} catch (boost::system::system_error& e) {
			log::error(logger_)() << "application::run() Error: " << e.what();
			return -1;
		}
		return 0;
	}

	void stop(void) {
		return;
	}
};


/*!
  コンストラクタ
 */
application::application(void) : impl_(nullptr) {
	impl_ = new application_impl();
}

/*!
  デストラクタ
 */
application::~application(void) {
	if (impl_) {
		delete impl_;
	}
	if (session_thread_ != nullptr) {
		session_thread_->join();
	}
	if (access_log_thread_ != nullptr) {
		access_log_thread_->join();
	}
}

/*!
  停止
 */
void application::stop(void) {
	stop_flag_ = true;
	impl_->stop();
	return;
}

/*!
  実行
 */
int application::run(void) {
	std::cout << "session: " << conf_.is_session_save_enabled() << std::endl;
	if (conf_.is_session_save_enabled()) {
		// Redisにセッションを保存する
		session_ = std::make_unique<session_manager>(conf_.get_session_redis_server(),
				conf_.get_session_redis_server_port());
		session_thread_ = std::make_unique<std::thread>([this] { session_->run(); });
	} else {
		session_ = std::make_unique<session_manager>();
	}

	// invoke access log thread
	if (access_logger_ != nullptr) {
		access_log_thread_ = std::make_unique<std::thread>([this] { access_logger_->run(); });
	}

	neosystem::http2::init_http2_static_headers_table();
	neosystem::http2::init_huffman();

	int result = impl_->run();

	http2::destruct_huffman_root();
	return result;
}

/*!
  logger等の初期化

  @param[in] conf_file confファイルのパス
 */
bool application::static_member_init(const std::string& conf_file) {
	if (!conf_file.empty()) {
		if (conf_.load(conf_file) == false) {
			return false;
		}
	}

	// log
	logger_.level(conf_.get_log_level());
	logger_.rotation_size(conf_.get_log_size());
	logger_.rotation_count(conf_.get_log_count());

	if (conf_.get_enable_access_log()) {
		access_logger_ = std::make_unique<async_access_logger>();
	}

	std::cout << conf_;
	return true;
}

/*!
  バージョン情報の表示
 */
void application::show_version(void) {
	std::cout << "Korat auth_gateway " << VERSION << std::endl;
	std::cout << "Copyright (C) 2017-2020  HIGASHIYAMA Yasunori (higashiyama.yasunori@gmail.com)" << std::endl;
	return;
}

void application::access_log(const std::shared_ptr<log_object>& log_obj) {
	if (log_obj == nullptr || access_logger_ == nullptr) {
		return;
	}
	access_logger_->dump(log_obj);
	return;
}

}
}
