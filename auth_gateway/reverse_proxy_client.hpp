#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_REVERSE_PROXY_CLIENT_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_REVERSE_PROXY_CLIENT_HPP_

#include <queue>

#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/intrusive_ptr.hpp>

#include "application.hpp"
#include "http_response_header.hpp"
#include "cache_holder.hpp"
#include "log.hpp"
#include "http_common.hpp"
#include "async_access_logger.hpp"


namespace poppo {
namespace auth_gateway {

inline constexpr const std::size_t BUFFER_SIZE = 8192 * 10;
inline constexpr const std::size_t RECV_HEADER_BUFFER_SIZE = 4096 * 20;

inline constexpr const char *ERROR_RESULT = 
	"HTTP/1.0 500 Internal Server Error\r\n"
	"Connection: close\r\n"
	"Content-Length: 0\r\n"
	"\r\n";

using namespace neosystem::wg;
namespace util = neosystem::util;

template<typename Session>
class reverse_proxy_client : private boost::noncopyable {
private:
	using session_type = Session;
	using self_type = reverse_proxy_client<session_type>;

public:
	using reverse_proxy_client_ptr_type = boost::intrusive_ptr<self_type>;

private:
	int ref_count_;

	log::logger& logger_;

	object_cache<typename session_type::element_type::socket_type>& object_cache_;
	http::streambuf_cache& cache_;
	name_cache& name_cache_;

	boost::asio::ip::tcp::socket socket_;

	boost::asio::steady_timer timer_;

	boost::asio::ip::tcp::resolver resolver_;

	http::http_response_header response_header_;

	std::unique_ptr<boost::asio::streambuf> read_stream_;

	http::write_queue write_queue_;

	http::headers_type rewrite_headers_;

	http::recv_info recv_;
	bool recv_complete_flag_;
	std::queue<std::unique_ptr<boost::asio::streambuf>> wait_queue_;

	session_type session_;
	reverse_proxy_client_ptr_type next_;

	http::handler_memory handler_memory_;
	http::handler_memory write_handler_memory_;
	log_object::ptr_type log_obj_;

	void handle_connect(const boost::system::error_code& error, boost::asio::ip::tcp::resolver::iterator endpoint_iterator) {
		if (error == boost::asio::error::operation_aborted) return;

		if (!error) {
			//set_send_buffer_size(socket_);
			//set_receive_buffer_size(socket_);
			//set_tcp_option(socket_);

			// 書き込み開始
			auto *buf = write_queue_.front();

			async_write_impl(buf);

			// レスポンスヘッダ受信開始
			async_header_read_impl(2);
			return;
		}

		if (endpoint_iterator != boost::asio::ip::tcp::resolver::iterator()) {
			boost::system::error_code ec;
			socket_.close(ec);
			boost::asio::ip::tcp::endpoint endpoint = *endpoint_iterator;
			reverse_proxy_client_ptr_type self(this);
			socket_.async_connect(
				endpoint,
				make_custom_alloc_handler(handler_memory_, std::bind(&self_type::handle_connect, std::move(self), std::placeholders::_1, ++endpoint_iterator)))
				;
			return;
		}

		log::error(logger_)() << S_ << error.message();

		auto buf = cache_.get(ERROR_RESULT);
		response_to_client(buf);
		return;
	}

	void response_to_client(std::unique_ptr<boost::asio::streambuf>& buf) {
		if (session_ == nullptr) {
			wait_queue_.push(std::move(buf));
			log::info(logger_)() << S_ << "session_ == nullptr";
			return;
		}
		if (!wait_queue_.empty()) flush_wait_queue();
		session_->response_to_client(buf);
		return;
	}

	void async_header_read_impl(std::size_t s, bool need_new_buffer = true) {
		if (need_new_buffer) {
			read_stream_ = cache_.get();
			read_stream_->prepare(RECV_HEADER_BUFFER_SIZE);
		}
		reverse_proxy_client_ptr_type self(this);
		boost::asio::async_read(
			socket_, *read_stream_, boost::asio::transfer_at_least(s),
			make_custom_alloc_handler(handler_memory_, std::bind(&self_type::handle_read_header,
																 self, std::placeholders::_1))
			);
		return;
	}

	void async_content_read_impl(bool need_new_buffer = true) {
		std::size_t size = 1;
		if (need_new_buffer) {
			read_stream_ = cache_.get();
		}
		if (recv_.is_chunked || recv_.content_length == 0) {
			read_stream_->prepare(BUFFER_SIZE);
			if (recv_.content_length > 0 && recv_.content_length > recv_.complete_length) {
				size = recv_.content_length - recv_.complete_length;
			}
		} else {
			std::size_t tmp = recv_.content_length - recv_.complete_length;
			if (tmp > BUFFER_SIZE) {
				read_stream_->prepare(BUFFER_SIZE);
				size = BUFFER_SIZE;
			} else {
				read_stream_->prepare(tmp);
				size = tmp;
				//size = 1;
			}
		}
		reverse_proxy_client_ptr_type self(this);

		boost::asio::async_read(socket_, *read_stream_, boost::asio::transfer_at_least(size), make_custom_alloc_handler(handler_memory_,
			[this, self = std::move(self)](const boost::system::error_code& error, std::size_t) {
				if (error && read_stream_->size() == 0) {
					if (recv_.is_chunked == false && recv_.has_content_length == false) {
						complete();
						return;
					}
					log::error(logger_)() << S_ << " Error: " << error.message() << " " << read_stream_->size();
					return;
				}

				handle_read_content(0);
			}));
		return;
	}

	void handle_read_header(const boost::system::error_code& error) {
		boost::asio::streambuf& read_stream = *read_stream_;

		auto it = boost::asio::buffers_begin(read_stream.data());
		auto end = boost::asio::buffers_end(read_stream.data());

		auto result = response_header_.parse(it, end);
		if (std::get<0>(result) == http::http_response_header::result_type::indeterminate) {
			if (error) {
				log::error(logger_)() << S_ << " Error: " << error.message();
				//util::socket_shutdown(socket_);
				return;
			}
			// ある程度長いヘッダは捨てる
			if (read_stream.size() > 64 * 1024) {
				return;
			}
			async_header_read_impl(1, false);
			return;
		}
		if (std::get<0>(result) != http::http_response_header::result_type::good) {
			// ヘッダのパースエラー
			log::error(logger_)() << S_ << "HTTP header parse error.";
			return;
		}

		std::size_t header_length = std::distance(boost::asio::buffers_begin(read_stream.data()), std::get<1>(result));
		if (!rewrite_headers_.empty()) {
			auto new_header = create_new_request_header(read_stream, header_length, response_header_, rewrite_headers_);
			response_to_client(new_header);
			header_length = 0;
		}

		recv_.complete_flag = false;
		recv_.complete_length = 0;
		if (response_header_.is_chunked() == false) {
			if (response_header_.get_status_code_str() == "304") {
				recv_.has_content_length = true;
			} else {
				recv_.has_content_length = response_header_.get_has_content_length();
			}
			recv_.content_length = response_header_.get_content_length();
			recv_.is_chunked = false;

			handle_read_content(header_length);
			return;
		}

		// チャンク
		recv_.content_length = 0;
		recv_.is_chunked = true;

		handle_read_content(header_length);
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
				if ((len = http::get_chunk_size(it, end, chunk_size)) == 0) {
					bool need_new_buffer = false;
					if (offset > 0) {
						if (offset == read_stream_->size()) {
							response_to_client(read_stream_);
							need_new_buffer = true;
						} else {
							auto tmp_stream = cache_.move_buffer(*read_stream_, offset);
							response_to_client(tmp_stream);
							need_new_buffer = false;
						}
					}
					async_content_read_impl(need_new_buffer);
					return;
				}
				if (chunk_size == 0) recv_.complete_flag = true;
				recv_.complete_length = 0;
				recv_.content_length = len + 2 + chunk_size + 2;
			}

			if ((recv_.complete_length + read_stream_size) >= recv_.content_length) {
				// チャンク読み込み完了
				if ((recv_.complete_length + read_stream_size) == recv_.content_length) {
					// 一致
					recv_.content_length = 0;
					recv_.complete_length = 0;

					response_to_client(read_stream_);
					if (recv_.complete_flag == false) {
						async_content_read_impl();
					} else {
						complete();
					}
					return;
				}

				// コピーを書き込む
				std::size_t write_size = recv_.content_length - recv_.complete_length;
				auto begin = boost::asio::buffers_begin(read_stream_->data());
				auto end = boost::asio::buffers_end(read_stream_->data());
				bool need_new_buffer = false;
				for (auto it = begin + write_size + offset; ; ) {
					if ((len = http::get_chunk_size(it, end, chunk_size)) == 0) {
						if (write_size + offset == read_stream_->size()) {
							response_to_client(read_stream_);
							need_new_buffer = true;
						} else {
							auto tmp_stream = cache_.move_buffer(*read_stream_, write_size + offset);
							response_to_client(tmp_stream);
							need_new_buffer = false;
						}

						recv_.content_length = 0;
						recv_.complete_length = 0;

						if (recv_.complete_flag == false) {
							async_content_read_impl(need_new_buffer);
						} else {
							complete();
						}
						return;
					}
					if (chunk_size == 0) recv_.complete_flag = true;
					std::size_t tmp_write_size = write_size + len + 2 + chunk_size + 2;
					if (read_stream_size < tmp_write_size) {
						response_to_client(read_stream_);
						recv_.content_length = len + 2 + chunk_size + 2;
						recv_.complete_length = read_stream_size - write_size;
						async_content_read_impl();
						return;
					}
					write_size = tmp_write_size;
					it = begin + write_size + offset;
				}
				return;
			}

			recv_.complete_length += read_stream_size;
			response_to_client(read_stream_);
			async_content_read_impl();
			return;
		}

		// chunkなし
		if (recv_.has_content_length == false) {
			// closeまで読み込む
			response_to_client(read_stream_);
			async_content_read_impl();
			return;
		}
		recv_.complete_length += read_stream_size;
		response_to_client(read_stream_);
		if (recv_.complete_length < recv_.content_length) {
			async_content_read_impl();
			return;
		}
		complete();
		//util::socket_shutdown(socket_);
		//session_.reset();
		return;
	}

	void async_write_impl(boost::asio::streambuf *buf) {
		reverse_proxy_client_ptr_type self(this);
		boost::asio::async_write(socket_, *buf,
								 make_custom_alloc_handler(write_handler_memory_, std::bind(&self_type::handle_async_write, std::move(self), std::placeholders::_1, std::placeholders::_2)));
		return;
	}

	void handle_async_write(const boost::system::error_code error, std::size_t) {
		if (error) {
			log::error(logger_)() << S_ << " Error: " << error.message();
			//util::socket_shutdown(socket_);
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

	void destruct(void) {
		release_session();
		util::socket_shutdown(socket_);
		if (log_obj_ != nullptr) {
			log_obj_.reset();
		}
		return;
	}

	void init_impl(void) {
		ref_count_ = 0;
		response_header_.clear();
		recv_.init();
		recv_complete_flag_ = false;
		next_.reset();

		while (!wait_queue_.empty()) {
			wait_queue_.pop();
		}

		rewrite_headers_.clear();
		return;
	}

	void flush_wait_queue(void) {
		while (!wait_queue_.empty()) {
			auto tmp = std::move(wait_queue_.front());
			wait_queue_.pop();
			session_->response_to_client(tmp);
		}
		return;
	}

	void complete(void) {
		if (log_obj_ != nullptr) {
			log_obj_->set_request_complete_time();
			log_obj_->set_http_status(response_header_.get_status_code_str().c_str());
			application::access_log(log_obj_);
			log_obj_.reset();
		}
		recv_complete_flag_ = true;
		if (session_ == nullptr) {
			return;
		}

		if (!wait_queue_.empty()) {
			flush_wait_queue();
		}

		if (next_ == nullptr) {
			session_->notify_complete();
			session_.reset();
			return;
		}

		next_->set_session(session_);
		next_ = nullptr;
		return;
	}

	void set_session(const session_type& s) {
		release_session();
		session_ = s;
		if (!wait_queue_.empty()) flush_wait_queue();
		if (recv_complete_flag_) {
			complete();
		}
		return;
	}

	void release_session(void) {
		if (session_ == nullptr) {
			return;
		}
		session_->release_client(this);
		session_.reset();
		return;
	}

	std::unique_ptr<boost::asio::streambuf> create_new_request_header(
		boost::asio::streambuf& buf, std::size_t move_size, const http::http_response_header& header,
		const http::headers_type& additional_header) {

		const char *p = boost::asio::buffer_cast<const char *>(buf.data());
		const char *q = p;
		std::size_t len;
		for (len = 0; ; ++len) {
			if (*p == '\n') break;
			++p;
		}
		++len;

		auto tmp_stream = cache_.get();
		tmp_stream->prepare(move_size);
		std::ostream os(&(*tmp_stream));

		os.write(q, len);

		// write vector
		http::headers_type merge;
		http::merge_headers(merge, header.get_headers(), additional_header);
		for (const auto& h : merge) {
			os << h.name << ": " << h.value << "\r\n";
		}
		os << "\r\n";

		buf.consume(move_size);
		return tmp_stream;
	}

public:
	reverse_proxy_client(boost::asio::io_context& io_context, cache_holder<typename session_type::element_type::socket_type>& holder)
		: ref_count_(0), logger_(application::get_logger()),
		object_cache_(holder.get_object_cache()), cache_(holder.get_cache()), name_cache_(holder.get_name_cache()),
		socket_(io_context),
		timer_(io_context), resolver_(io_context), recv_complete_flag_(false), session_(nullptr), next_(nullptr) {
	}

	reverse_proxy_client(boost::asio::io_context& io_context, const session_type& p,
											   cache_holder<typename session_type::element_type::socket_type>& holder)
		: ref_count_(0), logger_(application::get_logger()),
		object_cache_(holder.get_object_cache()), cache_(holder.get_cache()), name_cache_(holder.get_name_cache()),
		socket_(io_context),
		timer_(io_context), resolver_(io_context), recv_complete_flag_(false), session_(p), next_(nullptr) {
	}

	~reverse_proxy_client(void) {
		destruct();
	}

	void init(void) {
		release_session();
		init_impl();
		return;
	}

	void init(const session_type& p) {
		release_session();
		session_ = p;
		init_impl();
		return;
	}

	void start(const log_object::ptr_type& log_obj, const char *host, const char *port, std::unique_ptr<boost::asio::streambuf>& buf) {
		log_obj_ = log_obj;
		log_obj_->set_request_start_time();
		write_queue_.push(buf);
		boost::asio::ip::tcp::resolver::query query(host, port);

		reverse_proxy_client_ptr_type self(this);
		resolver_.async_resolve(query, make_custom_alloc_handler(handler_memory_,
			[this, self](const boost::system::error_code& error, boost::asio::ip::tcp::resolver::iterator endpoint_iterator) {
				if (error == boost::asio::error::operation_aborted) return;
				if (error) {
					log::error(logger_)() << S_ << " Error: resolve failed. (message: " << error.message() << ")";
					auto buf1 = cache_.get(ERROR_RESULT);
					response_to_client(buf1);
					return;
				}

				boost::asio::ip::tcp::endpoint endpoint = *endpoint_iterator;
				socket_.async_connect(
					endpoint,
					make_custom_alloc_handler(handler_memory_, std::bind(&self_type::handle_connect, self, std::placeholders::_1, ++endpoint_iterator))
					);
				return;
			}));
		return;
	}

	void async_write(std::unique_ptr<boost::asio::streambuf>& buf) {
		if (write_queue_.push(buf) == false) {
			// 前のバッファの書き込み完了待ち
			//log::info(logger_)() << "write waiting...";
			return;
		}
		async_write_impl(write_queue_.front());
		return;
	}

	void append_rewrite_header(const char *name, const std::string& value) {
		//log::info(logger_)() << S_ << "append header (" << name << ": " << value << ")";
		http::header h;
		h.name = name;
		h.value = value;
		rewrite_headers_.push_back(h);
		return;
	}

	void set_next(reverse_proxy_client *p) {
		if (next_ == nullptr) {
			next_ = p;
			if (recv_complete_flag_) {
				complete();
			}
		} else {
			next_->set_next(p);
		}
		return;
	}

	void add_ref(void) {
		++ref_count_;
		return;
	}

	void release(void) {
		if(--ref_count_ == 0) {
			if (object_cache_.release(this) == false) {
				delete this;
				return;
			}
			destruct();
		}
		return;
	}
};

template<typename T>
void intrusive_ptr_add_ref(reverse_proxy_client<T> *p) {
	p->add_ref();
	return;
}

template<typename T>
void intrusive_ptr_release(reverse_proxy_client<T> *p) {
	p->release();
	return;
}

}
}

#endif
