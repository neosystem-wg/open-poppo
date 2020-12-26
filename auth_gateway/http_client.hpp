#ifndef NEOSYSTEM_HTTP_HTTP_CLIENT_HPP_
#define NEOSYSTEM_HTTP_HTTP_CLIENT_HPP_

#include <iostream>
#include <queue>

#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/ssl.hpp>

#include "log.hpp"
#include "http_response_header.hpp"


namespace neosystem {
namespace http {

using namespace neosystem::wg;

enum class http_client_error {
	response_header_parse_error = 0x1,
	response_header_size_error = 0x2,
	response_body_size_limit_over = 0x4,
};

class http_client_status {
private:
	const boost::system::error_code error_code_;
	const uint32_t client_error_;

public:
	http_client_status(void) : client_error_(0) {
	}

	http_client_status(const boost::system::error_code& error_code) : error_code_(error_code), client_error_(0) {
	}

	http_client_status(const uint32_t client_error) : client_error_(client_error) {
	}

	explicit operator bool(void) const {
		if (error_code_ || client_error_ != 0) return true;
		return false;
	}

	const boost::system::error_code& get_error_code(void) const { return error_code_; }
	uint32_t get_client_error(void) const { return client_error_; }

	void dump(std::ostream& stream) const {
		if (error_code_) {
			stream << error_code_;
		} else if (client_error_ != 0) {
			stream << "http error (" << client_error_ << ")";
		}
		return;
	}
};

std::ostream& operator<<(std::ostream& stream, const http_client_status& s) {
	s.dump(stream);
	return stream;
}

template<typename SocketType>
class http_client_impl : public std::enable_shared_from_this<http_client_impl<SocketType>>, private boost::noncopyable {
public:
	enum class callback_flag_type {
		first = 0x1,
		last = 0x2,
	};

	using callback_func_type = std::function<void (const http_client_status&, const http_response_header&, const char *, size_t)>;
	using callback_func_type2 = std::function<void (uint8_t, const http_client_status&, const http_response_header&, const char *, size_t)>;

protected:
	using socket_type = SocketType;
	using self_type = http_client_impl<SocketType>;

	log::logger& logger_;

	streambuf_cache& cache_;

	boost::asio::io_context::strand strand_;

	boost::asio::steady_timer timer_;

	boost::asio::ip::tcp::resolver resolver_;

	/** コールバック */
	bool first_call_;
	callback_func_type func_;
	callback_func_type2 func2_;

	http_response_header response_header_;

	std::unique_ptr<boost::asio::streambuf> read_stream_;

	write_queue write_queue_;

	recv_info recv_;

	std::unique_ptr<boost::asio::streambuf> response_body_stream_;

	virtual socket_type& get_socket2(void) = 0;

	virtual boost::asio::ip::tcp::socket& get_socket(void) = 0;

	virtual void socket_shutdown(void) = 0;

	virtual void connect_complete(void) = 0;

	void async_write_impl(boost::asio::streambuf *buf) {
		auto self = std::enable_shared_from_this<self_type>::shared_from_this();
		boost::asio::async_write(get_socket2(), *buf,
				strand_.wrap(std::bind(&http_client_impl::handle_async_write, self, std::placeholders::_1, std::placeholders::_2)));
		return;
	}

	void handle_async_write(const boost::system::error_code error, std::size_t) {
		if (error) {
			log::error(logger_)() << S_ << "Write Error: " << error.message();
			call_callback_function(error);
			socket_shutdown();
			return;
		}
	
		auto *buf = write_queue_.pop(cache_);
		if (buf == nullptr) {
			// 書き込み待ちなし
			return;
		}
		// 次の書き込み対象を処理する
		async_write_impl(buf);
		return;
	}

	void handle_read_header(const boost::system::error_code& error) {
		const boost::asio::streambuf& read_stream = *read_stream_;

		auto it = boost::asio::buffers_begin(read_stream.data());
		auto end = boost::asio::buffers_end(read_stream.data());

		auto result = response_header_.parse(it, end);
		if (std::get<0>(result) == http_response_header::result_type::indeterminate) {
			if (error) {
				log::error(logger_)() << S_ << "Error: " << error.message();
				socket_shutdown();
				// callback
				call_callback_function(error);
				return;
			}
			// ある程度長いヘッダは捨てる
			if (read_stream.size() > 64 * 1024) {
				call_callback_function(http_client_error::response_header_size_error);
				return;
			}
			async_header_read_impl(1, false);
			return;
		}
		if (std::get<0>(result) != http_response_header::result_type::good) {
			// ヘッダのパースエラー
			log::error(logger_)() << S_ << "HTTP header parse error.";
			call_callback_function(http_client_error::response_header_parse_error);
			return;
		}
	
		// ヘッダ長
		std::size_t header_length = std::distance(boost::asio::buffers_begin(read_stream_->data()), std::get<1>(result));
		// consume
		read_stream_->consume(header_length);
	
		recv_.complete_flag = false;
		recv_.complete_length = 0;
		if (response_header_.is_chunked() == false) {
			// チャンクなし
			if (response_header_.get_status_code_str() == "304") {
				recv_.has_content_length = true;
			} else {
				recv_.has_content_length = response_header_.get_has_content_length();
			}
			recv_.content_length = response_header_.get_content_length();
			recv_.is_chunked = false;
			handle_read_content(0);
			return;
		}
	
		// チャンク
		recv_.content_length = 0;
		recv_.is_chunked = true;
	
		handle_read_content(0);
		return;
	}

	void async_content_read_impl(bool need_new_buffer = true) {
		std::size_t size = 1;
		if (need_new_buffer) {
			read_stream_ = std::make_unique<boost::asio::streambuf>();
			read_stream_->prepare(8192 * 10);
		}
		auto self = std::enable_shared_from_this<self_type>::shared_from_this();
		boost::asio::async_read(get_socket2(), *read_stream_, boost::asio::transfer_at_least(size),
							strand_.wrap([this, self](const boost::system::error_code& error, std::size_t) {
			if (error && read_stream_->size() == 0) {
				// callback
				if (recv_.is_chunked == false && recv_.has_content_length == false) {
					// closeまで読み込み完了
					call_callback_function();
				} else {
					log::error(logger_)() << S_ << "Read Error: " << error.message();
					call_callback_function(error);
				}
				return;
			}
	
			handle_read_content(0);
		}));
		return;
	}

	void handle_read_content(std::size_t offset) {
		std::size_t read_stream_size = read_stream_->size() - offset;
	
		if (recv_.is_chunked) {
			std::size_t len, chunk_size = 1;
	
			if (recv_.content_length == 0) {
				// チャンクサイズ不明の場合
				auto it = boost::asio::buffers_begin(read_stream_->data()) + offset;
				auto end = boost::asio::buffers_end(read_stream_->data());
				if ((len = get_chunk_size(it, end, chunk_size)) == 0) {
					bool need_new_buffer = false;
					async_content_read_impl(need_new_buffer);
					return;
				}
				if (chunk_size == 0) recv_.complete_flag = true;
				recv_.complete_length = 0;
				recv_.content_length = len + 2 + chunk_size + 2;
				recv_.chunk_offset = len + 2;

				//log::info(logger_)() << "chunk length == " << recv_.content_length;
			}
	
			if ((recv_.complete_length + read_stream_size) >= recv_.content_length) {
				// チャンク読み込み完了
				if ((recv_.complete_length + read_stream_size) == recv_.content_length) {
					// 一致
					recv_.content_length = 0;
					recv_.complete_length = 0;
	
					if (read_stream_size >= 2 + recv_.chunk_offset) {
						call_callback_function(read_stream_, recv_.chunk_offset,
											   read_stream_size - 2 - recv_.chunk_offset, recv_.complete_flag);
					}
					recv_.chunk_offset = 0;
					if (recv_.complete_flag == false) {
						async_content_read_impl();
					}
					return;
				}

				// 残りある
				std::size_t move_size = recv_.content_length - recv_.complete_length;
				auto tmp_stream = cache_.move_buffer(*read_stream_, move_size);
				if (tmp_stream->size() > 2 + recv_.chunk_offset) {
					call_callback_function(tmp_stream, recv_.chunk_offset, tmp_stream->size() - 2 - recv_.chunk_offset, false);
				}

				recv_.content_length = 0;
				recv_.complete_length = 0;
				recv_.chunk_offset = 0;

				// 再帰
				handle_read_content(0);
				return;
			}
	
			recv_.complete_length += read_stream_size;
			if (read_stream_size > recv_.chunk_offset) {
				call_callback_function(read_stream_, recv_.chunk_offset, read_stream_size - recv_.chunk_offset, false);
			}
			recv_.chunk_offset = 0;
			async_content_read_impl();
			return;
		}
	
		// chunkなし
		if (recv_.has_content_length == false) {
			// closeまで読み込む
			call_callback_function(read_stream_, 0, read_stream_->size(), false);
			async_content_read_impl();
			return;
		}
		recv_.complete_length += read_stream_size;
		if (recv_.complete_length < recv_.content_length) {
			call_callback_function(read_stream_, 0, read_stream_->size(), false);
			async_content_read_impl();
			return;
		} else {
			call_callback_function(read_stream_, 0, read_stream_->size(), true);
		}
		// callback
		socket_shutdown();
		return;
	}

	void call_callback_function(void) {
		http_client_status s;
		call_callback_function(s);
		return;
	}

	void call_callback_function(http_client_error e) {
		http_client_status s((uint32_t) e);
		call_callback_function(s);
		return;
	}

	void call_callback_function(const boost::system::error_code& e) {
		http_client_status s(e);
		call_callback_function(s);
		return;
	}

	void call_callback_function(const http_client_status& s) {
		if (func_ != nullptr) {
			if (response_body_stream_ != nullptr) {
				const char *p = boost::asio::buffer_cast<const char *>(response_body_stream_->data());
				func_(s, response_header_, p, response_body_stream_->size());
			} else {
				func_(s, response_header_, nullptr, 0);
			}
			func_ = nullptr;
		} else if (func2_ != nullptr) {
			uint8_t flag = (uint8_t) callback_flag_type::last;
			if (first_call_) {
				flag |= (uint8_t) callback_flag_type::first;
			}
			func2_(flag, s, response_header_, nullptr, 0);
			func2_ = nullptr;
		}
		first_call_ = false;
		return;
	}

	void call_callback_function(std::unique_ptr<boost::asio::streambuf>& buf,
								std::size_t offset, std::size_t size, bool is_last) {
		http_client_status s;
		call_callback_function(s, buf, offset, size, is_last);
		return;
	}

	void call_callback_function(const boost::system::error_code& e, std::unique_ptr<boost::asio::streambuf>& buf,
								std::size_t offset, std::size_t size, bool is_last) {
		http_client_status s(e);
		call_callback_function(s, buf, offset, size, is_last);
		return;
	}

	void call_callback_function(const http_client_status& s, std::unique_ptr<boost::asio::streambuf>& buf,
								std::size_t offset, std::size_t size, bool is_last) {
		if (func_ != nullptr) {
			if (response_body_stream_ == nullptr) {
				response_body_stream_ = cache_.get();
			}

			std::ostream stream(&(*response_body_stream_));
			if (size > 0) {
				const char *p = boost::asio::buffer_cast<const char *>(buf->data());
				stream.write(p + offset, size);
			}

			if (is_last) {
				const char *p = boost::asio::buffer_cast<const char *>(response_body_stream_->data());
				func_(s, response_header_, p, response_body_stream_->size());
				func_ = nullptr;
				cache_.release(response_body_stream_);
			}
		} else if (func2_ != nullptr) {
			uint8_t flag_type = 0x0;
			if (first_call_) {
				flag_type |= (uint8_t) callback_flag_type::first;
			}
			if (is_last) {
				flag_type |= (uint8_t) callback_flag_type::last;
			}
			const char *p = boost::asio::buffer_cast<const char *>(buf->data());
			func2_(flag_type, s, response_header_, p + offset, size);
			if (is_last) {
				func2_ = nullptr;
			}
		}
		first_call_ = false;
		return;
	}

	void async_header_read_impl(std::size_t s, bool need_new_buffer = true) {
		if (need_new_buffer) {
			read_stream_ = std::make_unique<boost::asio::streambuf>();
			read_stream_->prepare(4096 * 20);
		}
		boost::asio::async_read(
			get_socket2(), *read_stream_,
			boost::asio::transfer_at_least(s),
			strand_.wrap(std::bind(&http_client_impl::handle_read_header,
					std::enable_shared_from_this<self_type>::shared_from_this(), std::placeholders::_1))
			);
		return;
	}

	void handle_connect(const boost::system::error_code& error, boost::asio::ip::tcp::resolver::iterator endpoint_iterator) {
		if (error == boost::asio::error::operation_aborted) return;

		if (!error) {
			connect_complete();
			return;
		}

		if (endpoint_iterator != boost::asio::ip::tcp::resolver::iterator()) {
			boost::system::error_code ec;
			get_socket().close(ec);
			boost::asio::ip::tcp::endpoint endpoint = *endpoint_iterator;
			auto self = std::enable_shared_from_this<self_type>::shared_from_this();
			get_socket().async_connect(
				endpoint,
				strand_.wrap(std::bind(&http_client_impl::handle_connect, self, std::placeholders::_1, ++endpoint_iterator))
				);
			return;
		}
		log::error(logger_)() << S_ << error.message();
		call_callback_function(error);
		return;
	}

	void start_resolve(const char *host, const char *port) {
		boost::asio::ip::tcp::resolver::query query(host, port);
		auto self = std::enable_shared_from_this<self_type>::shared_from_this();

		if constexpr (std::is_same<socket_type, boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>::value) {
			if (!SSL_set_tlsext_host_name(get_socket2().native_handle(), host)) {
				log::error(logger_)() << S_ << "Error";
			}
		}

		resolver_.async_resolve(query,
				strand_.wrap([this, self](const boost::system::error_code& error, boost::asio::ip::tcp::resolver::iterator endpoint_iterator) {
			if (error == boost::asio::error::operation_aborted) return;
			if (error) {
				log::error(logger_)() << S_ << "Error: resolve failed. (message: " << error.message() << ")";
				call_callback_function(error);
				return;
			}
		
			boost::asio::ip::tcp::endpoint endpoint = *endpoint_iterator;
			get_socket().async_connect(
				endpoint,
				strand_.wrap(std::bind(&http_client_impl::handle_connect, self, std::placeholders::_1, ++endpoint_iterator))
				);
			return;
		}));
		return;
	}

	http_client_impl(log::logger& logger, boost::asio::io_context& io_context, streambuf_cache& cache) :
		logger_(logger), cache_(cache), strand_(io_context), timer_(io_context), resolver_(io_context), first_call_(true) {
	}

	http_client_impl(log::logger& logger, boost::asio::io_context& io_context, streambuf_cache& cache, const callback_func_type& func) :
		logger_(logger), cache_(cache), strand_(io_context), timer_(io_context), resolver_(io_context), first_call_(true), func_(func) {
	}

	http_client_impl(log::logger& logger, boost::asio::io_context& io_context, streambuf_cache& cache, const callback_func_type2& func) :
		logger_(logger), cache_(cache), strand_(io_context), timer_(io_context), resolver_(io_context), first_call_(true), func2_(func) {
	}

public:
	virtual ~http_client_impl(void) {
		//socket_shutdown();
	}

	void async_write(std::unique_ptr<boost::asio::streambuf>& buf) {
		if (write_queue_.push(buf) == false) {
			// 前のバッファの書き込み完了待ち
			return;
		}
		async_write_impl(write_queue_.front());
		return;
	}
};

class https_client : public http_client_impl<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> {
protected:
	using self_type = https_client;

	boost::asio::ssl::context ssl_context_;

	socket_type socket_;

	boost::asio::ip::tcp::socket& get_socket(void) {
		auto& s = socket_.lowest_layer();
		return *((boost::asio::ip::tcp::socket *) &s);
	}

	socket_type& get_socket2(void) {
		return socket_;
	}

	void socket_shutdown(void) {
		boost::system::error_code ec;
		socket_.shutdown(ec);
		socket_.lowest_layer().close(ec);
		return;
	}

	void connect_complete(void) {
		auto self = shared_from_this();

		socket_.async_handshake(
			boost::asio::ssl::stream_base::client,
			[this, self](const boost::system::error_code& error) {
				if (error) {
					log::error(logger_)() << S_ << "handshake error " + error.message();
					call_callback_function(error);
					return;
				}

				// 書き込み開始
				async_write_impl(write_queue_.front());

				// レスポンスヘッダ受信開始
				async_header_read_impl(2);
				return;
			});
		return;
	}

public:
	https_client(log::logger& logger, boost::asio::io_context& io_context, streambuf_cache& cache) :
		http_client_impl(logger, io_context, cache), ssl_context_(boost::asio::ssl::context::tlsv12), socket_(io_context, ssl_context_) {
	}

	https_client(log::logger& logger, boost::asio::io_context& io_context, streambuf_cache& cache, const callback_func_type& func) :
		http_client_impl(logger, io_context, cache, func), ssl_context_(boost::asio::ssl::context::tlsv12), socket_(io_context, ssl_context_) {
	}

	https_client(log::logger& logger, boost::asio::io_context& io_context, streambuf_cache& cache, const callback_func_type2& func) :
		http_client_impl(logger, io_context, cache, func), ssl_context_(boost::asio::ssl::context::tlsv12), socket_(io_context, ssl_context_) {
	}

	static std::shared_ptr<self_type> create(log::logger& logger, boost::asio::io_context& io_context, streambuf_cache& cache) {
		return std::make_shared<self_type>(logger, io_context, cache);
	}

	static std::shared_ptr<self_type> create(log::logger& logger, boost::asio::io_context& io_context,
											 streambuf_cache& cache, const callback_func_type& func) {
		return std::make_shared<self_type>(logger, io_context, cache, func);
	}

	virtual ~https_client(void) {
		socket_shutdown();
	}

	void start(const char *host, const char *port, std::unique_ptr<boost::asio::streambuf>& buf) {
		log::debug(logger_)() << "start http client: " << host  << ":" << port;
		write_queue_.push(buf);
		start_resolve(host, port);
		return;
	}
};

class http_client : public http_client_impl<boost::asio::ip::tcp::socket> {
protected:
	using self_type = http_client;

	socket_type socket_;

	boost::asio::ip::tcp::socket& get_socket(void) {
		return socket_;
	}

	socket_type& get_socket2(void) {
		return socket_;
	}

	void socket_shutdown(void) {
		neosystem::util::socket_shutdown(socket_);
		return;
	}

	void connect_complete(void) {
		// 書き込み開始
		async_write_impl(write_queue_.front());

		// レスポンスヘッダ受信開始
		async_header_read_impl(2);
		return;
	}

public:
	http_client(log::logger& logger, boost::asio::io_context& io_context, streambuf_cache& cache, const callback_func_type& func) :
		http_client_impl(logger, io_context, cache, func), socket_(io_context) {
	}

	http_client(log::logger& logger, boost::asio::io_context& io_context, streambuf_cache& cache, const callback_func_type2& func) :
		http_client_impl(logger, io_context, cache, func), socket_(io_context) {
	}

	static std::shared_ptr<self_type> create(log::logger& logger, boost::asio::io_context& io_context,
											 streambuf_cache& cache, const callback_func_type& func) {
		return std::make_shared<self_type>(logger, io_context, cache, func);
	}

	static std::shared_ptr<self_type> create(log::logger& logger, boost::asio::io_context& io_context,
											 streambuf_cache& cache, const callback_func_type2& func) {
		return std::make_shared<self_type>(logger, io_context, cache, func);
	}

	virtual ~http_client(void) {
		socket_shutdown();
	}

	void start(const char *host, const char *port, std::unique_ptr<boost::asio::streambuf>& buf) {
		write_queue_.push(buf);
		start_resolve(host, port);
		return;
	}

	void start(const char *host, const char *port, std::unique_ptr<boost::asio::streambuf>& header,
			std::unique_ptr<boost::asio::streambuf>& body) {
		write_queue_.push(header);
		write_queue_.push(body);
		start_resolve(host, port);
		return;
	}
};

}
}

#endif
