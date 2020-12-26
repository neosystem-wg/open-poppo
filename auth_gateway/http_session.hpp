#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_HTTP_SESSION_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_HTTP_SESSION_HPP_

#include <string>
#include <fstream>
#include <memory>
#include <type_traits>

#include <boost/noncopyable.hpp>
#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/intrusive_ptr.hpp>

#include "http_request_header.hpp"
#include "application.hpp"
#include "cache_holder.hpp"
#include "session.hpp"
#include "http_session_reply.hpp"
#include "reverse_proxy_client.hpp"
#include "twitter_login.hpp"
#include "slack_login.hpp"
#include "github_login.hpp"
#include "poppo_id_getter.hpp"
#include "session_manager.hpp"
#include "http2_session.hpp"
#include "http_session_socket.hpp"
#include "https_session_socket.hpp"
#include "async_access_logger.hpp"
#include "auth_history.hpp"


namespace poppo {
namespace auth_gateway {

constexpr int DEFAULT_TIMEOUT_MS = 30 * 1000;
constexpr std::size_t REQUEST_LIMIT = 4096;

using namespace neosystem::wg;
namespace util = neosystem::util;
namespace http = neosystem::http;

template<typename SocketType>
class http_session : private boost::noncopyable {
public:
	enum class request_type {
		proxy,
		logout,
	};

	enum class init_session_result_type {
	};

	using socket_type = SocketType;

	using self_type = http_session<socket_type>;

	using ptr_type = boost::intrusive_ptr<self_type>;

	using current_session_ptr_type = session_ptr_type;

private:
	using reverse_proxy_client_type = reverse_proxy_client<ptr_type>;

	int ref_count_;

	neosystem::wg::log::logger& logger_;
	const config& conf_;

	cache_holder<socket_type>& holder_;
	object_cache<socket_type>& object_cache_;
	http::streambuf_cache& cache_;

	socket_type socket_;

	boost::asio::steady_timer timer_;

	std::unique_ptr<boost::asio::streambuf> read_stream_;

	http::http_request_header request_header_;

	http::write_queue write_queue_;

	http::recv_info recv_;

	reverse_proxy_client_type *client_;
	http_session_reply reply_;

	http::handler_memory handler_memory_;
	http::handler_memory timer_handler_memory_;
	http::handler_memory write_handler_memory_;

	std::string session_id_;
	session_ptr_type current_session_;

	request_type request_type_;
	std::unique_ptr<boost::asio::streambuf> request_stream_;

	bool is_login(void) const {
		if (current_session_ == nullptr) {
			return false;
		}
		if (current_session_->get_poppo_id() == "") {
			return false;
		}
		return true;
	}

	void async_header_read_for_keep_alive(void) {
		request_header_.clear();
		recv_.init();
		//http_session_ptr_type self(this);

		//// 受信タイマ
		//timer_.expires_from_now(std::chrono::milliseconds(DEFAULT_TIMEOUT_MS));
		//timer_.async_wait(make_custom_alloc_handler(timer_handler_memory_, [this, self = std::move(self)](const boost::system::error_code& ec) {
		//	if (ec) return;
		//	socket_.socket_shutdown();
		//}));

		if (read_stream_ == nullptr || read_stream_->size() == 0) {
			// ヘッダの非同期受信開始
			async_header_read_impl(2);
		} else {
			handle_read_header(boost::system::error_code());
		}
		return;
	}

	void async_header_read(void) {
		if (socket_.is_open() ==false) {
			log::info(logger_)() << "closed";
			return;
		}

		request_header_.clear();
		recv_.init();
		ptr_type self(this);

		// 受信タイマ
		timer_.expires_from_now(std::chrono::milliseconds(DEFAULT_TIMEOUT_MS));
		timer_.async_wait(make_custom_alloc_handler(timer_handler_memory_, [this, self = std::move(self)](const boost::system::error_code& ec) {
			if (ec) return;
			socket_.socket_shutdown();
			return;
		}));

		// ヘッダの非同期受信開始
		async_header_read_impl(2);
		return;
	}

	void handle_read_header(const boost::system::error_code& error) {
		boost::asio::streambuf& read_stream = *read_stream_;

		auto it = boost::asio::buffers_begin(read_stream.data());
		auto end = boost::asio::buffers_end(read_stream.data());

		auto result = request_header_.parse(it, end);
		if (std::get<0>(result) == http::http_request_header::result_type::indeterminate) {
			if (error) {
				if (read_stream.size() > 0) {
					log::error(logger_)() << S_ << " Error: " << error.message();
				}
				socket_.socket_shutdown_receive();
				return;
			}
			// ある程度長いヘッダは捨てる
			if (read_stream.size() > 64 * 1024) return;
			async_header_read_impl(1, false);
			return;
		}
		if (std::get<0>(result) != http::http_request_header::result_type::good) {
			// ヘッダのパースエラー
			log::error(logger_)() << S_ << "HTTP header parse error.";
			return;
		}

		bool is_https = traits::is_https<socket_type>::value;
		if (is_https == false) {
			is_https = is_xfp_https(request_header_);
		}
		reply_.set_https(is_https);

		request_stream_.reset();
		std::size_t header_length = std::distance(boost::asio::buffers_begin(read_stream.data()), std::get<1>(result));
		if (conf_.is_session_save_enabled()) {
			// Redisへの保存が有効な場合
			if (current_session_ == nullptr) {
				if (init_session_for_redis(header_length) == false) {
					return;
				}
			}
		} else {
			if (init_session() == false) {
				// エラー
				auto buf = cache_.get_503();
				async_write(buf);
				return;
			}
		}
		reply(read_stream, header_length);
		return;
	}

	void async_header_read_impl(std::size_t s, bool need_new_buffer = true) {
		ptr_type self(this);
		if (need_new_buffer) read_stream_ = cache_.get();
		read_stream_->prepare(DEFAULT_RECV_BUFFER_SIZE);
		boost::asio::async_read(
			socket_.get_socket(), *read_stream_,
			boost::asio::transfer_at_least(s),
			make_custom_alloc_handler(handler_memory_, [this, self = std::move(self)](const boost::system::error_code& error, std::size_t) {
				timer_.cancel();

				handle_read_header(error);
				return;
			})
		);
		return;
	}

	void async_content_read_impl(bool need_new_buffer = true) {
		std::size_t size = recv_.content_length - recv_.complete_length;
		if (size > DEFAULT_RECV_BUFFER_SIZE) size = DEFAULT_RECV_BUFFER_SIZE;
		if (need_new_buffer) read_stream_ = cache_.get();
		read_stream_->prepare(size);
		ptr_type self(this);

		boost::asio::async_read(socket_.get_socket(), *read_stream_, boost::asio::transfer_at_least(size),
							make_custom_alloc_handler(handler_memory_, [this, self = std::move(self)](const boost::system::error_code& error, std::size_t) {
			if (error) {
				log::error(logger_)() << S_ << " Error: " << error.message();
				handle_request();
				return;
			}

			handle_read_content();
			return;
		}));
		return;
	}

	void handle_read_content(void) {
		std::size_t read_stream_size = read_stream_->size();

		if (recv_.content_length == 0) {
			// closeまで読み込む
			send_to_server(read_stream_);
			async_content_read_impl();
			return;
		}

		if (recv_.complete_length + read_stream_size > recv_.content_length) {
			// 次のリクエストが読み込めている
			std::size_t move_size = read_stream_size - ((recv_.complete_length + read_stream_size) - recv_.content_length);
			auto buf = cache_.move_buffer(*read_stream_, move_size);
			send_to_server(buf);
			handle_request();
			async_header_read_for_keep_alive();
			return;
		}
		recv_.complete_length += read_stream_size;
		send_to_server(read_stream_);
		if (recv_.complete_length < recv_.content_length) {
			async_content_read_impl();
			return;
		}

		handle_request();

		// keep-aliveの場合の考慮
		//client_ = nullptr;
		async_header_read_for_keep_alive();
		return;
	}

	void async_write_impl(void) {
		ptr_type self(this);
		auto& buffers = write_queue_.get_buffers();
		boost::asio::async_write(
			socket_.get_socket(),
			buffers,
			make_custom_alloc_handler(write_handler_memory_, std::bind(&http_session::handle_async_write, self, std::placeholders::_1, std::placeholders::_2))
			);
		return;
	}

	void async_write(std::unique_ptr<boost::asio::streambuf>& buf) {
		if (write_queue_.push(buf) == false) {
			// 前のバッファの書き込み完了待ち
			//log::info(logger_)() << "write waiting...";
			return;
		}
		async_write_impl();
		return;
	}

	void handle_async_write(const boost::system::error_code error, std::size_t) {
		//log::info(logger_)() << S_ << "async write handler";
		if (error) {
			log::error(logger_)() << S_ << " Error: " << error.message();
			//socket_.socket_shutdown();
			return;
		}

		write_queue_.clear_writing_buffer(cache_);
		if (write_queue_.is_empty()) {
			// 書き込み待ちなし
			return;
		}
		// 次の書き込み対象を処理する
		async_write_impl();
		return;
	}

	void handle_read_pri(void) {
		std::size_t size = recv_.content_length - recv_.complete_length;
		ptr_type self(this);

		boost::asio::async_read(socket_.get_socket(),
							*read_stream_, boost::asio::transfer_at_least(size),
							make_custom_alloc_handler(handler_memory_, [this, self = std::move(self)](const boost::system::error_code& error, std::size_t) {
			if (error) {
				log::error(logger_)() << S_ << " Error: " << error.message();
				return;
			}

			if (is_http2_pri(*read_stream_)) {
				read_stream_->consume(6);
				auto tmp_stream(cache_.move_buffer(*read_stream_, read_stream_->size()));
				ptr_type self2(this);
				auto session = http2_session<self_type>::create(self2, holder_);
				current_session_.reset();
				session->start(tmp_stream);
			}
			return;
		}));
		return;
	}

	bool is_http2_pri(const boost::asio::streambuf& buf) {
		if (buf.size() < 6) {
			return false;
		}
		const char *p = boost::asio::buffer_cast<const char *>(buf.data());
		if (strncmp(p, "SM\r\n\r\n", 6) == 0) {
			// OK
			return true;
		}
		return false;
	}

	void send_to_server(std::unique_ptr<boost::asio::streambuf>& buf) {
		if (client_ == nullptr) {
			switch (request_type_) {
			case request_type::logout:
				if (request_stream_ == nullptr) {
					request_stream_ = cache_.get();
				}
				util::append_buffer(*buf, *request_stream_);
				if (request_stream_->size() > REQUEST_LIMIT) {
					auto reply_buf = cache_.get_503();
					async_write(reply_buf);
					log::info(logger_)() << S_ << "Invalid size";
				}
				break;
			case request_type::proxy:
				break;
			}
			return;
		}
		client_->async_write(buf);
		return;
	}

	void destruct(void) {
		request_header_.clear();
		session_id_ = "";
		current_session_.reset();
		socket_.socket_shutdown();
		return;
	}

	bool check_csrf_header(const http::http_request_header& header) {
		if (current_session_ == nullptr) return false;

		std::string token = header.find_header(conf_.get_csrf_header_name());
		if (token == "") return false;

		if (token != current_session_->get_csrf_token()) return false;
		return true;
	}

	void start_oauth1(const oauth1_server_config& conf) {
		ptr_type self(this);

		twitter_login::ptr_type l = std::make_shared<twitter_login>(logger_, socket_.get_io_context(), cache_);

		l->start_oauth1(conf, [this, self = std::move(self), l](int /*http_status*/, const std::string& oauth_token) {
			if (oauth_token == "") {
				auto buf = cache_.get_503();
				async_write(buf);
				return;
			}

			current_session_->set_request_token(oauth_token);

			auto buf = reply_.oauth1_redirect(current_session_->get_oauth1_config(), oauth_token,
											  session_id_, current_session_->get_csrf_token());
			async_write(buf);
			return;
		});
		return;
	}

	void get_oauth1_access_token(const oauth1_server_config& conf, const std::string& oauth_verifier, const std::string& oauth_token) {
		ptr_type self(this);

		twitter_login::ptr_type l = std::make_shared<twitter_login>(logger_, socket_.get_io_context(), cache_);

		l->get_oauth1_access_token(conf, oauth_verifier, oauth_token, [this, self = std::move(self), l](int /*http_status*/, const std::string& id) {
			if (id == "") {
				auto buf = cache_.get_503();
				async_write(buf);
				return;
			}
			get_poppo_id(auth_provider::TWITTER, id);
			return;
		});
		return;
	}

	void get_oauth2_access_token(const oauth2_server_config::ptr_type& conf, const std::string& code) {
		switch (conf->get_auth_provider()) {
		case auth_provider::SLACK:
			get_oauth2_access_token_for_slack(conf, code);
			break;
		case auth_provider::GITHUB:
			get_oauth2_access_token_for_github(conf, code);
			break;
		default:
			break;
		}
		return;
	}

	void get_oauth2_access_token_for_slack(const oauth2_server_config::ptr_type& conf, const std::string& code) {
		slack_login::ptr_type l = std::make_shared<slack_login>(
			logger_, conf, socket_.get_io_context(), cache_);

		ptr_type self(this);
		l->login([this, self = std::move(self), l](int /*http_status*/, const std::string& id) {
			if (id == "") {
				auto buf = cache_.get_503();
				async_write(buf);
				return;
			}
			get_poppo_id(auth_provider::SLACK, id);
			return;
		}, code);
		return;
	}

	void get_oauth2_access_token_for_github(const oauth2_server_config::ptr_type& conf, const std::string& code) {
		github_login::ptr_type l = std::make_shared<github_login>(
			logger_, conf, socket_.get_io_context(), cache_);

		ptr_type self(this);
		l->login([this, self = std::move(self), l](int /*http_status*/, const std::string& id) {
			if (id == "") {
				auto buf = cache_.get_503();
				async_write(buf);
				return;
			}
			get_poppo_id(auth_provider::GITHUB, id);
			return;
		}, code);
		return;
	}

	void get_poppo_id(auth_provider auth_p, const std::string& user_id) {
		ptr_type self(this);
		poppo_id_getter::ptr_type getter = std::make_shared<poppo_id_getter>(logger_, conf_, socket_.get_io_context(), cache_);
		if (conf_.get_enable_auth_history()) {
			std::string ip_addr;
			get_remote_endpoint(ip_addr);
			auth_history::ptr_type auth_h = std::make_shared<auth_history>(auth_p,
																		   ip_addr, request_header_.find_header("User-Agent"));
			getter->set_auth_history(auth_h);
		}
		getter->run([this, self = std::move(self), getter](std::unique_ptr<boost::asio::streambuf> buf, const std::string& poppo_id) {
			if (poppo_id == "") {
				async_write(buf);
				return;
			}

			if (session_id_ != "") {
				application::get_session().remove(session_id_);
			}
			session_id_ = "";
			if (put_session(poppo_id) == false) return;
			buf = reply_.redirect_to_login_success(session_id_, current_session_->get_csrf_token());
			async_write(buf);
			return;
		}, auth_p, user_id);
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

	bool init_session(void) {
		if (current_session_ != nullptr) {
			return true;
		}

		const auto& cookie = request_header_.get_cookie();
		auto cit = cookie.find(SESSION_ID_KEY_NAME);
		if (cit == cookie.end()) {
			return put_session();
		}

		session_id_ = cit->second;
		current_session_ = application::get_session().get(cit->second);
		if (current_session_ == nullptr) {
			return put_session();
		}
		current_session_->update_last_access_time();
		return true;
	}

	bool init_session_for_redis(std::size_t header_length) {
		const auto& cookie = request_header_.get_cookie();
		auto cit = cookie.find(SESSION_ID_KEY_NAME);
		if (cit == cookie.end()) {
			put_session();
			return true;
		}
		current_session_ = application::get_session().get(cit->second);
		if (current_session_ != nullptr) {
			session_id_ = cit->second;
			current_session_->update_last_access_time();
			return true;
		}
		ptr_type self(this);
		auto f = [this, header_length, self = std::move(self)](
				const boost::system::error_code& ec, redis_command_status, const session_ptr_type& p) {
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
			reply(*read_stream_, header_length);
			return;
		};
		session_id_ = cit->second;
		application::get_session().get(session_id_, socket_.get_io_context(), f);
		return false;
	}

	void reply(boost::asio::streambuf& read_stream, std::size_t header_length) {
		const std::string& request_path = request_header_.get_request_path();

		std::string check_path;
		http::remove_get_parameter(request_path, check_path);

		// logout
		if (check_path == conf_.get_logout_path() && request_header_.get_request_method() == http::http_method_type::POST) {
			handle_logout(read_stream, header_length);
			return;
		}

		// oauth1のコールバック
		auto auth_conf = conf_.get_oauth1_server_config_for_callback(check_path);
		if (auth_conf != nullptr) {
			// callback
			std::unordered_map<std::string, std::string> m;
			http::parse_http_url(request_path, m);

			auto verifier_it = m.find("oauth_verifier");
			if (verifier_it == m.end()) {
				auto buf = cache_.get_503();
				async_write(buf);
				return;
			}

			if (current_session_ == nullptr) return;
			get_oauth1_access_token(*auth_conf, verifier_it->second, current_session_->get_request_token());
			return;
		}

		auto oauth2_conf = conf_.get_oauth2_server_config_for_callback(check_path);
		if (oauth2_conf != nullptr) {
			std::unordered_map<std::string, std::string> m;
			http::parse_http_url(request_path, m);

			if (current_session_ == nullptr) {
				auto buf = cache_.get_503();
				async_write(buf);
				return;
			}
			std::string session_state = current_session_->get_state();
			//log::info(logger_)() << "state: " << m["state"] << ", state(session): " << session_state;
			if (session_state != m["state"]) {
				log::error(logger_)() << S_ "state error";
				auto buf = cache_.get_503();
				async_write(buf);
				return;
			}

			get_oauth2_access_token(oauth2_conf, m["code"]);
			return;
		}

		auth_conf = conf_.get_oauth1_server_config(check_path);
		if (auth_conf != nullptr) {
			if (current_session_ != nullptr && current_session_->get_poppo_id() != "") {
				auto buf = reply_.redirect_to_login_success(session_id_, current_session_->get_csrf_token());
				async_write(buf);
				return;
			}
			// 認証ページ
			current_session_->set_oauth1_config(auth_conf);
			start_oauth1(*auth_conf);
			return;
		}

		// oauth2ログイン
		oauth2_conf = conf_.get_oauth2_server_config(check_path);
		if (oauth2_conf != nullptr) {
			if (current_session_ != nullptr && current_session_->get_poppo_id() != "") {
				auto buf = reply_.redirect_to_login_success(session_id_, current_session_->get_csrf_token());
				async_write(buf);
				return;
			}
			std::string state;
			util::generate_oauth2_state(state);
			current_session_->set_state(state);
			auto buf = reply_.start_oauth2(*oauth2_conf, session_id_, current_session_->get_csrf_token(), state);
			async_write(buf);
			return;
		}

		if (conf_.get_enable_http2()) {
			if (request_header_.is_http2_pri()) {
				read_stream.consume(header_length);
				if (read_stream.size() >= 6) {
					if (is_http2_pri(read_stream)) {
						read_stream.consume(6);
						auto tmp_stream(cache_.move_buffer(read_stream, read_stream.size()));
						ptr_type self(this);
						auto session = http2_session<self_type>::create(self, holder_);
						current_session_.reset();
						session->start(tmp_stream);
						return;
					}
					return;
				}
				recv_.content_length = 6;
				recv_.complete_length = read_stream.size();
				handle_read_pri();
				return;
			} else if (request_header_.is_http2()) {
				if (request_header_.get_http2_settings() != "") {
					read_stream.consume(header_length);
					auto tmp_stream(cache_.move_buffer(read_stream, read_stream.size()));
					auto decode_buf = cache_.get();
					util::decode_base64(request_header_.get_http2_settings().c_str(),
										request_header_.get_http2_settings().size(), *decode_buf);
					ptr_type self(this);
					auto session = http2_session<self_type>::create(self, holder_);
					current_session_.reset();
					session->start(tmp_stream, *decode_buf, request_header_);
					return;
				}
				return;
			}
		}

		auto proxy_conf = conf_.get_proxy_config(request_header_.get_host(), check_path);
		if (proxy_conf != nullptr) {
			//log::info(logger_)() << S_ << "proxy: " << request_path;
			reply_proxy(read_stream, header_length, proxy_conf);
			return;
		}

		auto static_conf = conf_.get_static_page_config(check_path);
		if (static_conf != nullptr) {
			// static page
			// TODO
			return;
		}

		// 404
		log::info(logger_)() << "404: " << request_path;
		auto buf = cache_.get_404();
		async_write(buf);
		return;
	}

	bool reply_proxy(boost::asio::streambuf& read_stream, std::size_t header_length,
			const proxy_config::ptr_type& proxy_conf) {
		const std::string& request_path = request_header_.get_request_path();

		if (proxy_conf->need_csrf_check() && need_csrf_check(request_header_)) {
			if (check_csrf_header(request_header_) == false) {
				auto buf = cache_.get_400();
				async_write(buf);
				return false;
			}
		}
		if (proxy_conf->need_auth() == false && is_login() == false) {
			// 認証なし
			if (proxy_conf->get_path() != "") {
				std::string new_request_path;
				http::replace_path(proxy_conf->get_request_path(), proxy_conf->get_path(), request_path, new_request_path);
				log::debug(logger_)() << S_ << request_path << "->" << new_request_path;

				auto tmp_stream = create_new_request_header(read_stream, header_length, new_request_path, request_header_);
				reply_proxy(proxy_conf, tmp_stream);
			} else {
				std::unique_ptr<boost::asio::streambuf> tmp_stream(cache_.move_buffer(read_stream, header_length));
				reply_proxy(proxy_conf, tmp_stream);
			}
		} else {
			if (proxy_conf->need_auth() != false && current_session_->get_poppo_id() == "") {
				// CORS
				if (proxy_conf->has_cors_config() && request_header_.get_request_method() == http::http_method_type::OPTIONS) {
					auto buf = reply_.response_preflight(proxy_conf, request_header_);
					async_write(buf);
					return true;
				}
				// まだログインしてない
				if (proxy_conf->is_response_401()) {
					reply_401(proxy_conf);
				} else {
					auto buf = reply_.reply_login();
					async_write(buf);
				}
				return false;
			}

			if (proxy_conf->get_path() != "") {
				std::string new_request_path;
				replace_path(proxy_conf, proxy_conf->get_request_path(), proxy_conf->get_path(), request_path, new_request_path);
				log::info(logger_)() << S_ << request_path << "->" << new_request_path;

				auto tmp_stream = create_new_request_header(read_stream, header_length - 2, new_request_path, request_header_);

				read_stream.consume(2);
				append_poppo_id(*tmp_stream);

				reply_proxy(proxy_conf, tmp_stream);
			} else {
				std::unique_ptr<boost::asio::streambuf> tmp_stream(cache_.move_buffer(read_stream, header_length - 2));

				read_stream.consume(2);
				append_poppo_id(*tmp_stream);

				reply_proxy(proxy_conf, tmp_stream);
			}
		}

		if (request_header_.get_content_length() <= 0) {
			// keep-aliveの場合の考慮
			async_header_read_for_keep_alive();
			return false;
		}
		recv_.content_length = request_header_.get_content_length();
		handle_read_content();
		return true;
	}

	void reply_proxy(const proxy_config::ptr_type& proxy_conf, std::unique_ptr<boost::asio::streambuf>& req) {
		ptr_type self(this);

		reverse_proxy_client_type *ptr = object_cache_.get_client();
		if (client_ == nullptr) {
			if (ptr == nullptr) {
				ptr = new reverse_proxy_client_type(socket_.get_io_context(), self, holder_);
			} else {
				ptr->init(self);
			}
		} else {
			if (ptr == nullptr) {
				ptr = new reverse_proxy_client_type(socket_.get_io_context(), holder_);
			} else {
				ptr->init();
			}
			client_->set_next(ptr);
		}
		if (proxy_conf->has_cors_config()) {
			auto cors_conf = proxy_conf->get_cors_config();

			if (request_header_.get_request_method() == http::http_method_type::OPTIONS) {
				auto buf = reply_.response_preflight(proxy_conf, request_header_);
				async_write(buf);
				return;
			}

			// Originチェック
			std::string origin(request_header_.find_header("Origin"));
			if (origin != "") {
				if (cors_conf->is_allow_origin(origin) == false) {
					auto buf = cache_.get_403();
					async_write(buf);
					return;
				}
				ptr->append_rewrite_header("Access-Control-Allow-Origin", origin);
			}

			// allow methods
			if (cors_conf->has_allow_methods()) {
				ptr->append_rewrite_header("Access-Control-Allow-Methods", cors_conf->get_allow_methods());
			}

			// allow header
			if (cors_conf->has_allow_headers()) {
				ptr->append_rewrite_header("Access-Control-Allow-Headers", cors_conf->get_allow_headers());
			}

			// allow credential
			if (cors_conf->is_allow_credentials()) {
				ptr->append_rewrite_header("Access-Control-Allow-Credentials", "true");
			}
		}
		auto log_obj = log_object::create(request_header_);
		client_ = ptr;
		ptr->start(log_obj, proxy_conf->get_host().c_str(), proxy_conf->get_port().c_str(), req);
		return;
	}

	void handle_request_logout(void) {
		if (request_stream_ == nullptr || request_stream_->size() <= 0) {
			log::info(logger_)() << S_ << "Invalid logout request";
			auto buf = cache_.get_503();
			async_write(buf);
			return;
		}
		if (current_session_ == nullptr) {
			log::info(logger_)() << S_ << "Invalid logout request";
			auto buf = cache_.get_503();
			async_write(buf);
			return;
		}

		std::string request_string(boost::asio::buffer_cast<const char *>(request_stream_->data()), request_stream_->size());
		std::unordered_map<std::string, std::string> result;

		http::parse_http_post(request_string, result);
		auto it = result.find(POST_CSRF_TOKEN_NAME);
		if (it == result.end()) {
			log::info(logger_)() << S_ << "Invalid logout request";
			auto buf = cache_.get_503();
			async_write(buf);
			return;
		}
		if (it->second != current_session_->get_csrf_token()) {
			log::info(logger_)() << S_ << "Invalid logout request  " << it->second << ", " << current_session_->get_csrf_token();
			auto buf = cache_.get_503();
			async_write(buf);
			return;
		}

		logout();

		auto buf = reply_.reply_login();
		async_write(buf);
		return;
	}

	void handle_request(void) {
		switch (request_type_) {
		case request_type::proxy:
			break;
		case request_type::logout:
			handle_request_logout();
			return;
		}
		return;
	}

	void handle_logout(boost::asio::streambuf& read_stream, std::size_t header_length) {
		read_stream.consume(header_length);

		request_type_ = request_type::logout;
		recv_.content_length = request_header_.get_content_length();
		if (recv_.content_length <= 0) {
			log::info(logger_)() << S_ << "Invalid logout request";
			auto buf = cache_.get_503();
			async_write(buf);
			return;
		}
		handle_read_content();
		return;
	}

	void reply_401(const proxy_config::ptr_type& proxy_conf) {
		if (proxy_conf->has_cors_config() == false) {
			auto buf = cache_.get_401();
			async_write(buf);
			return;
		}
		auto buf = cache_.get();
		auto cors_conf = proxy_conf->get_cors_config();
		std::ostream os(&(*buf));

		os << "HTTP/1.1 401 Unauthorized\r\n";
		os << "Connection: close\r\n";
		os << "Content-Length: 0\r\n";

		std::string origin(request_header_.find_header("Origin"));
		if (origin != "") {
			if (cors_conf->is_allow_origin(origin) == false) {
				buf = cache_.get_403();
				async_write(buf);
				return;
			}
			os << "Access-Control-Allow-Origin: " << origin << "\r\n";
		}

		if (cors_conf->has_allow_methods()) {
			os << "Access-Control-Allow-Methods: " << cors_conf->get_allow_methods() << "\r\n";
		}
		if (cors_conf->has_allow_headers()) {
			os << "Access-Control-Allow-Headers: " << cors_conf->get_allow_headers() << "\r\n";
		}
		if (cors_conf->is_allow_credentials()) {
			os << "Access-Control-Allow-Credentials: true\r\n";
		}
		os << "\r\n";
		async_write(buf);
		return;
	}

	void append_poppo_id(boost::asio::streambuf& tmp_stream) {
		std::ostream append_header_stream(&tmp_stream);
		append_header_stream << "X-POPPO-ID: " << current_session_->get_poppo_id() << "\r\n";
		append_header_stream << "\r\n";
		return;
	}

	std::unique_ptr<boost::asio::streambuf> create_new_request_header(
			boost::asio::streambuf& buf, std::size_t move_size, const std::string& new_request_path,
			const http::http_request_header& header) {
		const char *p = boost::asio::buffer_cast<const char *>(buf.data());
		std::size_t len;
		for (len = 0; ; ++len) {
			if (*p == '\n') break;
			++p;
		}
		++p;
		++len;

		auto tmp_stream = cache_.get();
		tmp_stream->prepare(move_size);
		std::ostream os(&(*tmp_stream));

		// write
		os << header.get_request_method_as_str() << " " << new_request_path << ((header.get_version() == 1.0) ? " HTTP/1.0\r\n" : " HTTP/1.1\r\n");

		os.write(p, move_size - len);
		buf.consume(move_size);
		return tmp_stream;
	}

	void replace_path(const proxy_config::ptr_type& proxy_conf, const std::string& config_request_path,
			const std::string& config_path, const std::string& request_path, std::string& new_request_path) {
		new_request_path = config_path;
		//if (config_path[config_path.size() - 1] != '/') {
		//	new_request_path += '/';
		//}

		new_request_path += (request_path.c_str() + config_request_path.size());

		if (proxy_conf->need_replace_poppo_id()) {
			new_request_path.replace(proxy_conf->get_replace_pos(), 10, current_session_->get_poppo_id());
		}
		if (new_request_path == "") {
			new_request_path = "/";
		}
		return;
	}

public:
	http_session(boost::asio::io_context& io_context, cache_holder<socket_type>& holder) :
		ref_count_(0), logger_(application::get_logger()), conf_(application::get_config()),
   		holder_(holder), object_cache_(holder.get_object_cache()), cache_(holder.get_cache()),
		socket_(io_context), timer_(io_context), client_(nullptr), reply_(conf_, cache_), request_type_(request_type::proxy) {
	}

	http_session(boost::asio::io_context& io_context, cache_holder<socket_type>& holder, boost::asio::ssl::context& ssl_context) :
		ref_count_(0), logger_(application::get_logger()), conf_(application::get_config()),
   		holder_(holder), object_cache_(holder.get_object_cache()), cache_(holder.get_cache()),
		socket_(io_context, ssl_context), timer_(io_context), client_(nullptr), reply_(conf_, cache_), request_type_(request_type::proxy) {
	}

	static ptr_type create(boost::asio::io_context& io_context, cache_holder<socket_type>& holder) {
		return ptr_type(new http_session<SocketType>(io_context, holder));
	}

	static ptr_type create(boost::asio::io_context& io_context, cache_holder<socket_type>& holder, boost::asio::ssl::context& ssl_context) {
		return ptr_type(new http_session<SocketType>(io_context, holder, ssl_context));
	}

	~http_session(void) {
		destruct();
	}

	void init_socket(boost::asio::io_context& io_context, boost::asio::ssl::context& ssl_context) {
		if constexpr (std::is_same<typename socket_type::socket_type, boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>::value) {
			socket_.init(io_context, ssl_context);
		}
		return;
	}

	void init(void) {
		ref_count_ = 0;
		client_ = nullptr;
		request_header_.clear();
		session_id_ = "";
		current_session_.reset();
		recv_.init();
		return;
	}

	void start(void) {
		//set_send_buffer_size(socket_.get_tcp_socket());
		//set_receive_buffer_size(socket_.get_tcp_socket());
		//set_tcp_option(socket_.get_tcp_socket());

		client_ = nullptr;
		session_id_ = "";
		current_session_.reset();
		if constexpr (std::is_same<typename socket_type::socket_type, boost::asio::ip::tcp::socket>::value) {
			// HTTP
			async_header_read();
		} else {
			// HTTPS
			ptr_type self(this);
			socket_.get_socket().async_handshake(boost::asio::ssl::stream_base::server,
				[this, self](const boost::system::error_code& error) {
					if (error) {
						log::error(logger_)() << S_ << error.message();
						socket_.socket_shutdown();
						return;
					}
					async_header_read();
					return;
				});
		}
		return;
	}

	void notify_complete(void) {
		if (request_header_.get_indeterminate_pos() > 0) {
			return;
		}

		//boost::system::error_code ec;
		//socket_.get_tcp_socket().shutdown(boost::asio::ip::tcp::socket::shutdown_receive, ec);
		socket_.socket_shutdown_receive();
		return;
	}

	boost::asio::ip::tcp::socket& socket(void) {
		return socket_.get_tcp_socket();
	}

	typename socket_type::socket_type& get_socket(void) {
		return socket_.get_socket();
	}

	boost::asio::io_context& get_io_context(void) {
		return socket_.get_io_context();
	}

	void socket_shutdown(void) {
		socket_.socket_shutdown();
		return;
	}

	void response_to_client(std::unique_ptr<boost::asio::streambuf>& buf, bool /*is_final*/ = false) {
		async_write(buf);
		return;
	}

	const std::string& get_session_id(void) const { return session_id_; }

	session_ptr_type get_current_session(void) const { return current_session_; }

	void get_remote_endpoint(std::string& str) {
		socket_.get_remote_endpoint(str);
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

	void release_client(reverse_proxy_client_type *p) {
		if (p == client_) {
			client_ = nullptr;
		}
		return;
	}

	void logout(void) {
		application::get_session().remove(session_id_);
		current_session_ = nullptr;
		log::info(logger_)() << S_ << "remove session: " << session_id_;
		return;
	}
};

template<typename SocketType>
void intrusive_ptr_add_ref(http_session<SocketType> *p) {
	p->add_ref();
	return;
}

template<typename SocketType>
void intrusive_ptr_release(http_session<SocketType> *p) {
	p->release();
	return;
}

}
}

#endif
