#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_HTTP2_SESSION_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_HTTP2_SESSION_HPP_

#include <cstring>
#include <iostream>
#include <string>
#include <fstream>
#include <memory>

#include <boost/noncopyable.hpp>
#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>

#include "http_request_header.hpp"
#include "cache_holder.hpp"
#include "http2_stream.hpp"
#include "http2_frame_header.hpp"
#include "http2_settings.hpp"
#include "http2_dynamic_headers_table.hpp"
#include "http_session_socket.hpp"
#include "session_manager.hpp"
#include "async_access_logger.hpp"


namespace poppo {
namespace auth_gateway {

constexpr std::size_t DEFAULT_RECV_BUFFER_SIZE = 4096 * 8;
constexpr const uint32_t MAX_STREAM_ID_INITIALI_VALUE = 0xFFFFFFFF;
constexpr const uint32_t INIIAL_MAX_FRAME_SIZE = 16384;
constexpr const uint32_t MAX_FRAME_SIZE = 16777215;
constexpr const uint32_t MAX_FLOW_CONTROL_WINDOW_SIZE = 2147483647;

constexpr const char *OK_101_HEADER = 
	"HTTP/1.1 101 Switching Protocols\r\n"
	"Connection: Upgrade\r\n"
	"Upgrade: h2c\r\n"
	"\r\n";

static const std::string CONNECTION_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

using namespace neosystem::wg;
namespace util = neosystem::util;
namespace http2 = neosystem::http2;

template<typename SessionType>
class http2_session : private boost::noncopyable {
public:
	using session_type = SessionType;
	using session_ptr_type = typename session_type::ptr_type;

	using socket_type = typename session_type::socket_type;

	using self_type = http2_session<session_type>;
	using ptr_type = boost::intrusive_ptr<self_type>;

private:
	using http2_stream_type = http2_stream<ptr_type, socket_type>;

	int ref_count_;

	neosystem::wg::log::logger& logger_;
	const config& conf_;

	session_ptr_type session_;

	std::string session_id_;
	session_type::current_session_ptr_type current_session_;

	cache_holder<socket_type>& holder_;
	http::streambuf_cache& cache_;

	//boost::asio::steady_timer timer_;

	http2::http2_frame_header header_;
	bool partial_flag_;
	std::size_t read_complete_length_;
	std::unique_ptr<boost::asio::streambuf> read_stream_;

	http::write_queue write_queue_;

	http::handler_memory handler_memory_;
	//http::handler_memory timer_handler_memory_;
	http::handler_memory write_handler_memory_;

	http::http_request_header request_header_;

	http2::http2_settings settings_;
	std::unordered_map<uint32_t, std::shared_ptr<http2_stream_type>> stream_map_;
	http2::http2_dynamic_headers_table headers_table_;

	std::unordered_map<std::string, std::shared_ptr<std::vector<std::function<void (void)>>>> redis_callback_map_;
	uint32_t header_receiving_stream_id_;
	uint32_t max_stream_id_;
	bool need_close_;
	std::size_t remote_window_size_;

	void notify_update_initial_window_size(int32_t w) {
		for (auto it = stream_map_.begin(); it != stream_map_.end(); ++it) {
			auto ptr = it->second;
			ptr->update_init_window_size(w);
		}
		return;
	}

	bool is_priority_frame(const http2::http2_frame_header& header) const {
		const uint8_t type = header.get_type();
		if (type == (uint8_t) http2::http2_frame_type::priority) {
			return true;
		}
		return false;
	}

	bool is_window_update_frame(const http2::http2_frame_header& header) const {
		const uint8_t type = header.get_type();
		if (type == (uint8_t) http2::http2_frame_type::window_update) {
			return true;
		}
		return false;
	}

	void clear_all_stream(void) {
		stream_map_.clear();
		return;
	}

	void response_goaway(uint32_t stream_id, uint32_t error_code) {
		auto frame_header_stream = cache_.get();
		http2::get_goaway_frame(*frame_header_stream, stream_id, error_code);
		if (error_code == http2::ERROR_CODE_PROTOCOL_ERROR) {
			async_write_and_close(frame_header_stream);
		} else {
			async_write(frame_header_stream);
		}
		clear_all_stream();
		return;
	}

	bool put_session_impl(void) {
		if (http::generate_session_id(session_id_) == false) {
			return false;
		}

		std::string csrf_token;
		if (util::generate_csrf_token(csrf_token) == false) {
			return false;
		}

		current_session_ = session::create();
		current_session_->set_csrf_token(csrf_token);
		return true;
	}

	bool put_session(const std::string& poppo_id) {
		if (put_session_impl() == false) {
			return false;
		}
		current_session_->set_poppo_id(poppo_id);
		application::get_session().put(session_id_, current_session_);
		return true;
	}

	bool put_session(void) {
		if (put_session_impl() == false) {
			return false;
		}
		application::get_session().put(session_id_, current_session_);
		return true;
	}

	void destruct(void) {
		session_ = nullptr;
		session_id_ = "";
		current_session_.reset();
		return;
	}

	void read_connection_preface(void) {
		ptr_type self(this);
		boost::asio::async_read(
			session_->get_socket(), *read_stream_,
			boost::asio::transfer_at_least(1),
			make_custom_alloc_handler(handler_memory_, [this, self = std::move(self)](const boost::system::error_code& error, std::size_t) {
				if (error && read_stream_->size() == 0) {
					if (error.value() != boost::asio::error::eof) {
						clear_all_stream();
						log::error(logger_)() << S_ << "read error (" << error.message() << ")";
					}
					session_->socket_shutdown();
					return;
				}
				handle_read_connection_preface();
				return;
			})
		);
		return;
	}

	void handle_read_connection_preface(void) {
		if (read_stream_->size() < CONNECTION_PREFACE.length()) {
			read_connection_preface();
			return;
		}
		const char *p = boost::asio::buffer_cast<const char *>(read_stream_->data());
		if (strncmp(p, CONNECTION_PREFACE.c_str(), CONNECTION_PREFACE.length()) != 0) {
			session_->socket_shutdown();
			return;
		}
		read_stream_->consume(CONNECTION_PREFACE.length());

		ptr_type self(this);
		auto http2stream = std::make_shared<http2_stream_type>(self, 0);
		stream_map_[0] = http2stream;
		http2stream->send_settings();

		handle_read();

		http2stream = std::make_shared<http2_stream_type>(self, 1);
		stream_map_[1] = http2stream;
		auto log_obj = log_object::create(request_header_);
		http2stream->response(log_obj, request_header_);
		return;
	}

	void read(std::size_t s, bool need_new_buffer = true) {
		if (need_new_buffer) {
			read_stream_ = cache_.get();
		}
		read_stream_->prepare(DEFAULT_RECV_BUFFER_SIZE);
		if (s > DEFAULT_RECV_BUFFER_SIZE) {
			s = DEFAULT_RECV_BUFFER_SIZE;
		}
		ptr_type self(this);
		boost::asio::async_read(
			session_->get_socket(), *read_stream_,
			boost::asio::transfer_at_least(s),
			make_custom_alloc_handler(handler_memory_, [this, self = std::move(self)](const boost::system::error_code& error, std::size_t) {
				if (error && read_stream_->size() == 0) {
					if (error.value() != boost::asio::error::eof) {
						clear_all_stream();
						log::error(logger_)() << S_ << "read error (" << error.message() << ")";
					}
					session_->socket_shutdown();
					return;
				}
				handle_read();
				return;
			})
		);
		return;
	}

	void handle_read(void) {
		std::shared_ptr<http2_stream_type> http2stream;
		if (partial_flag_) {
			http2stream = stream_map_[header_.get_stream_id()];
			if (http2stream == nullptr) {
				if (is_priority_frame(header_) == false) {
					response_goaway(header_.get_stream_id(), http2::ERROR_CODE_STREAM_CLOSED);
					return;
				}
			}
			if (header_.get_length() <= read_complete_length_ + read_stream_->size()) {
				std::size_t send_size = header_.get_length() - read_complete_length_;
				if (http2stream != nullptr) {
					const uint8_t flag = (read_complete_length_ == 0) ? (FRAME_BUF_TYPE_FIRST | FRAME_BUF_TYPE_LAST) : (FRAME_BUF_TYPE_LAST);
					if (http2stream->send_buffer(read_stream_, send_size, flag, header_) == false) {
						return;
					}
				}

				partial_flag_ = false;

				if (header_.get_length() == read_complete_length_ + read_stream_->size()) {
					read_complete_length_ = 0;
					cache_.release(read_stream_);
					read(1, true);
					return;
				}
				read_complete_length_ = 0;
				read_stream_->consume(send_size);
				handle_read();
			} else {
				// まだ途中
				if (http2stream != nullptr) {
					const uint8_t flag = (read_complete_length_ == 0) ? (FRAME_BUF_TYPE_FIRST) : (0x0);
					if (http2stream->send_buffer(read_stream_, read_stream_->size(), flag, header_) == false) {
						return;
					}
				}
				read_complete_length_ += read_stream_->size();
				cache_.release(read_stream_);
				read(header_.get_length() - read_complete_length_, true);
			}
			return;
		}

		if (read_stream_->size() < http2::HTTP2_STREAM_HEADER_SIZE) {
			read(1, false);
			return;
		}

		const uint8_t *p = boost::asio::buffer_cast<const uint8_t *>(read_stream_->data());
		header_.read_from_buffer(p, read_stream_->size());
		if (header_.get_stream_id() != 0 && header_.get_stream_id() % 2 == 0) {
			response_goaway(header_.get_stream_id(), http2::ERROR_CODE_PROTOCOL_ERROR);
			return;
		}

		ptr_type self(this);
		uint32_t stream_id = header_.get_stream_id();
		read_stream_->consume(http2::HTTP2_STREAM_HEADER_SIZE);

		if (read_stream_->size() == 0) {
			partial_flag_ = true;
			if (stream_map_.find(stream_id) == stream_map_.end()) {
				stream_map_[stream_id] = std::make_shared<http2_stream_type>(self, stream_id);
			}
			read_complete_length_ = 0;
			read(header_.get_length(), false);
			return;
		}

		if (stream_map_.find(stream_id) == stream_map_.end()) {
			if (max_stream_id_ != MAX_STREAM_ID_INITIALI_VALUE && stream_id <= max_stream_id_) {
				if (is_priority_frame(header_) || is_window_update_frame(header_)) {
					// PRIORITYフレームは何もしない
					if (header_.get_length() <= read_stream_->size()) {
						std::size_t send_size = header_.get_length();
						if (send_size == read_stream_->size()) {
							cache_.release(read_stream_);
							read(1, true);
							return;
						}
						read_stream_->consume(send_size);
						handle_read();
					} else {
						partial_flag_ = true;
						stream_map_[stream_id] = std::make_shared<http2_stream_type>(self, stream_id);
						read_complete_length_ = read_stream_->size();
						cache_.release(read_stream_);
						read(header_.get_length() - read_complete_length_, true);
					}
					return;
				}
				log::info(logger_)() << S_ << "stream id error (stream_id: " << stream_id <<
					", max: " << max_stream_id_ << ", type: " << ((uint32_t) header_.get_type()) << ")";
				response_goaway(stream_id, http2::ERROR_CODE_PROTOCOL_ERROR);
				return;
			}
			http2stream = std::make_shared<http2_stream_type>(self, stream_id);
			stream_map_[stream_id] = http2stream;
		} else {
			http2stream = stream_map_[header_.get_stream_id()];
			if (http2stream == nullptr) {
				http2stream = std::make_shared<http2_stream_type>(self, header_.get_stream_id());
				stream_map_[stream_id] = http2stream;
			}
		}

		if (header_.get_length() <= read_stream_->size()) {
			std::size_t send_size = header_.get_length();
			if (http2stream->send_buffer(read_stream_, send_size, FRAME_BUF_TYPE_FIRST | FRAME_BUF_TYPE_LAST, header_) == false) {
				return;
			}
			if (send_size == read_stream_->size()) {
				cache_.release(read_stream_);
				read(1, true);
				return;
			}
			read_stream_->consume(send_size);
			handle_read();
			return;
		}

		if (http2stream->send_buffer(read_stream_, read_stream_->size(), FRAME_BUF_TYPE_FIRST, header_) == false) {
			return;
		}
		partial_flag_ = true;
		read_complete_length_ = read_stream_->size();

		cache_.release(read_stream_);
		read(header_.get_length() - read_complete_length_, true);
		return;
	}

	void async_write_impl(void) {
		ptr_type self(this);
		auto& buffers = write_queue_.get_buffers();
		boost::asio::async_write(
			session_->get_socket(),
			buffers,
			make_custom_alloc_handler(write_handler_memory_, std::bind(&http2_session::handle_async_write, self, std::placeholders::_1, std::placeholders::_2))
			);
		return;
	}

	void handle_async_write(const boost::system::error_code error, std::size_t /*s*/) {
		//log::info(logger_)() << S_ << "write complete: " << s;
		if (error) {
			clear_all_stream();
			log::error(logger_)() << S_ << " Error: " << error.message();
			//socket_shutdown(socket_);
			return;
		}

		write_queue_.clear_writing_buffer(cache_);
		if (write_queue_.is_empty()) {
			// 書き込み待ちなし
			if (need_close_) {
				session_->socket_shutdown();
				clear_all_stream();
			}
			return;
		}
		// 次の書き込み対象を処理する
		async_write_impl();
		return;
	}

public:
	http2_session(session_ptr_type& session, cache_holder<socket_type>& holder)
		: ref_count_(0), logger_(application::get_logger()), conf_(application::get_config()),
		session_(session), session_id_(session->get_session_id()), current_session_(session->get_current_session()),
		holder_(holder), cache_(holder.get_cache()),
		/*timer_(session_->get_io_context()), */partial_flag_(false), read_complete_length_(0), header_receiving_stream_id_(0),
		max_stream_id_(MAX_STREAM_ID_INITIALI_VALUE), need_close_(false), remote_window_size_(65535) {

		if (session_id_ == "") {
			current_session_.reset();
		}
	}

	static ptr_type create(session_ptr_type& session, cache_holder<socket_type>& holder) {
		//return ptr_type(new http2_session(session, holder));
		return ptr_type(new self_type(session, holder));
	}

	~http2_session(void) {
		//log::info(logger_)() << S_ << "http2_session destruct";
		destruct();
	}

	bool is_header_receiving(void) const {
		if (header_receiving_stream_id_ == 0) {
			return false;
		}
		return true;
	}

	bool start_header_receive(uint32_t stream_id) {
		if (header_receiving_stream_id_ == 0) {
			header_receiving_stream_id_ = stream_id;
			return true;
		}
		return false;
	}

	void end_header_receive(void) {
		header_receiving_stream_id_ = 0;
		return;
	}

	void init(void) {
		partial_flag_ = false;
		read_complete_length_ = 0;
		return;
	}

	void start(std::unique_ptr<boost::asio::streambuf>& stream) {
		init();

		ptr_type self(this);
		auto http2stream = std::make_shared<http2_stream_type>(self, 0);
		stream_map_[0] = http2stream;
		//http2stream->send_settings();

		read_stream_ = std::move(stream);
		handle_read();
		return;
	}

	void start(std::unique_ptr<boost::asio::streambuf>& stream, const boost::asio::streambuf& settings,
			   const http::http_request_header& request_header) {
		init();
		uint32_t error_code = init_settings(settings);
		if (error_code != 0) {
			clear_all_stream();
			return;
		}
		read_stream_ = std::move(stream);

		request_header_ = request_header;

		auto tmp = cache_.get(OK_101_HEADER);
		async_write(tmp);

		read_connection_preface();
		return;
	}

	void async_write_and_close(std::unique_ptr<boost::asio::streambuf>& buf) {
		if (need_close_) {
			return;
		}
		need_close_ = true;
		if (write_queue_.push(buf) == false) {
			// 前のバッファの書き込み完了待ち
			//log::info(logger_)() << "write waiting...";
			return;
		}
		async_write_impl();
		return;
	}

	void async_write(std::unique_ptr<boost::asio::streambuf>& buf) {
		if (need_close_) {
			return;
		}
		if (write_queue_.push(buf) == false) {
			// 前のバッファの書き込み完了待ち
			//log::info(logger_)() << "write waiting...";
			return;
		}
		async_write_impl();
		return;
	}

	boost::asio::io_context& get_io_context(void) {
		return session_->get_io_context();
	}

	http::streambuf_cache& get_streambuf_cache(void) {
		return cache_;
	}

	name_cache& get_name_cache(void) {
		return holder_.get_name_cache();
	}

	http2::http2_dynamic_headers_table& get_headers_table(void) {
		return headers_table_;
	}

	uint32_t init_settings(const boost::asio::streambuf& buf) {
		auto size = buf.size();
		if (size == 0) {
			return 0;
		} else if (size % 6 != 0) {
			return http2::ERROR_CODE_PROTOCOL_ERROR;
		}
		const uint8_t *p = boost::asio::buffer_cast<const uint8_t *>(buf.data());
		//log::debug(logger_)() << "size: " << size;
		size = size / sizeof(struct http2::http2_settings_param);
		for (std::size_t i = 0; i < size; ++i) {
			const struct http2::http2_settings_param *tmp = (const struct http2::http2_settings_param *) (p + (i * sizeof(struct http2::http2_settings_param)));
			struct http2::http2_settings_param param;
			param.identifier = ntohs(tmp->identifier);
			param.value = ntohl(tmp->value);
			//log::debug(logger_)() << "identifier: " << param.identifier << ", value: " << param.value << ", i: " << i;
			switch (param.identifier) {
			case http2::SETTINGS_HEADER_TABLE_SIZE:
				settings_.set_header_table_size(param.value);
				break;
			case http2::SETTINGS_ENABLE_PUSH:
				if (param.value != 0 && param.value != 1) {
					return http2::ERROR_CODE_PROTOCOL_ERROR;
				}
				settings_.set_enable_push(param.value != 0);
				break;
			case http2::SETTINGS_MAX_CONCURRENT_STREAMS:
				settings_.set_max_concurrent_streams(param.value);
				break;
			case http2::SETTINGS_INITIAL_WINDOW_SIZE:
				if (MAX_FLOW_CONTROL_WINDOW_SIZE < param.value) {
					return http2::ERROR_CODE_FLOW_CONTROL_ERROR;
				}
				settings_.set_initial_window_size(param.value);
				notify_update_initial_window_size(param.value);
				break;
			case http2::SETTINGS_MAX_FRAME_SIZE:
				if (param.value > MAX_FRAME_SIZE || param.value < INIIAL_MAX_FRAME_SIZE) {
					return http2::ERROR_CODE_PROTOCOL_ERROR;
				}
				settings_.set_max_frame_size(param.value);
				break;
			case http2::SETTINGS_MAX_HEADER_LIST_SIZE:
				settings_.set_max_header_list_size(param.value);
				break;
			}
		}
		return 0;
	}

	const http2::http2_settings& get_settings(void) const {
		return settings_;
	}

	const std::string& get_session_id(void) const {
		return session_id_;
	}

	void set_state(const std::string& state) {
		if (current_session_ == nullptr) {
			put_session();
		}
		current_session_->set_state(state);
		return;
	}

	std::string get_csrf_token(void) {
		if (current_session_ == nullptr) {
			put_session();
		}
		return current_session_->get_csrf_token();
	}

	bool init_session(void) {
		if (current_session_ != nullptr) {
			current_session_->update_last_access_time();
			return true;
		}

		put_session();
		return true;
	}

	bool init_session(const std::string& session_id) {
		if (current_session_ != nullptr && session_id_ == session_id) {
			current_session_->update_last_access_time();
			return true;
		}

		session_id_ = session_id;
		current_session_ = application::get_session().get(session_id);
		if (current_session_ == nullptr) {
			std::string csrf_token;
			if (util::generate_csrf_token(csrf_token) == false) {
				return false;
			}

			current_session_ = session::create();
			current_session_->set_csrf_token(csrf_token);
			application::get_session().put(session_id_, current_session_);
		}
		current_session_->update_last_access_time();
		return true;
	}

	oauth1_server_config::ptr_type get_oauth1_config(void) {
		if (current_session_ == nullptr) {
			return nullptr;
		}
		return current_session_->get_oauth1_config();
	}

	void set_oauth1_config(const oauth1_server_config::ptr_type& auth_conf) {
		if (current_session_ == nullptr) {
			return;
		}
		current_session_->set_oauth1_config(auth_conf);
		return;
	}

	void set_request_token(const std::string& oauth_token) {
		if (current_session_ == nullptr) {
			return;
		}
		current_session_->set_request_token(oauth_token);
		return;
	}

	bool is_login(void) const {
		if (current_session_ != nullptr && current_session_->get_poppo_id() != "") {
			return true;
		}
		return false;
	}

	void update_session(const std::string& poppo_id) {
		if (session_id_ != "") {
			application::get_session().remove(session_id_);
		}
		session_id_ = "";
		if (put_session(poppo_id) == false) {
			return;
		}
		log::debug(logger_)() << S_ << "poppo_id: " << poppo_id << ", session_id: " << session_id_;
		return;
	}

	bool init_session_for_redis(const std::string& session_id, const std::function<void (void)>& func) {
		if (current_session_ != nullptr && session_id_ == session_id) {
			current_session_->update_last_access_time();
			return true;
		}

		session_id_ = session_id;
		current_session_ = application::get_session().get(session_id);
		if (current_session_ != nullptr) {
			current_session_->update_last_access_time();
			return true;
		}

		if (redis_callback_map_.contains(session_id)) {
			auto ptr = redis_callback_map_[session_id];
			ptr->push_back(func);
			return false;
		}

		auto func_list = std::make_shared<std::vector<std::function<void (void)>>>();
		func_list->push_back(func);
		redis_callback_map_[session_id] = func_list;

		// Redisへの保存が有効な場合
		ptr_type self(this);
		auto f = [this, self = std::move(self)](const boost::system::error_code& ec, redis_command_status, const session_type::current_session_ptr_type& p) {
			std::string tmp_session_id = session_id_;
			if (ec || p == nullptr) {
				// エラーまたはない場合は新規に作成
				if (ec) {
					log::error(logger_)() << S_ << ec.message();
				}
				put_session();
			} else {
				current_session_ = p;
				application::get_session().put(session_id_, current_session_);
				current_session_->update_last_access_time();
			}

			auto it = redis_callback_map_.find(tmp_session_id);
			if (it == redis_callback_map_.end()) {
				return;
			}
			auto ptr = it->second;
			redis_callback_map_.erase(it);
			if (ptr == nullptr) {
				return;
			}
			for (auto callback: *ptr) {
				callback();
			}
			return;
		};
		session_id_ = session_id;
		application::get_session().get(session_id, session_->get_io_context(), f);
		return false;
	}

	session_type::current_session_ptr_type get_current_session(void) const { return current_session_; }

	const http::http_request_header& get_http11_request_header(void) const { return request_header_; }

	void get_remote_endpoint(std::string& str) {
		session_->get_remote_endpoint(str);
		return;
	}

	bool update_window_size(int32_t w) {
		remote_window_size_ += w;
		//log::debug(logger_)() << "w: " << w << ", remote_window_size: " << remote_window_size_;
		if (remote_window_size_ > MAX_WINDOW_SIZE) {
			return false;
		}
		if (remote_window_size_ > 0) {
			for (auto it = stream_map_.begin(); it != stream_map_.end(); ++it) {
				auto ptr = it->second;
				ptr->response_send_wait_buf();
			}
		}
		return true;
	}

	void remove_from_map(uint32_t stream_id) {
		stream_map_.erase(stream_id);
		return;
	}

	std::size_t update_send_size(std::size_t s, std::size_t stream_remote_window_size) {

		std::size_t min_remote_window_size = (remote_window_size_ < stream_remote_window_size)
			? remote_window_size_ : stream_remote_window_size;

		if (s < min_remote_window_size) {
			remote_window_size_ -= s;
			return s;
		}
		s = min_remote_window_size;
		remote_window_size_ -= s;
		return s;
	}

	void set_max_stream_id(uint32_t stream_id) {
		if (max_stream_id_ == MAX_STREAM_ID_INITIALI_VALUE || max_stream_id_ < stream_id) {
			max_stream_id_ = stream_id;
		}
		return;
	}

	void socket_shutdown(void) {
		session_->socket_shutdown();
		return;
	}

	void add_ref(void) {
		++ref_count_;
		return;
	}

	void release(void) {
		if(--ref_count_ == 0) {
			delete this;
		}
		return;
	}

	void logout(void) {
		session_->logout();
		return;
	}
};

template<typename SessionType>
void intrusive_ptr_add_ref(http2_session<SessionType> *p) {
	p->add_ref();
	return;
}

template<typename SessionType>
void intrusive_ptr_release(http2_session<SessionType> *p) {
	p->release();
	return;
}

}
}

#endif
