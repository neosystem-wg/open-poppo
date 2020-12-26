#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_HTTP2_STREAM_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_HTTP2_STREAM_HPP_

#include <memory>
#include <sstream>

#include <boost/noncopyable.hpp>
#include <boost/asio.hpp>

#include "http2_frame_header.hpp"
#include "http_request_header.hpp"
#include "http2_request_header.hpp"
#include "http2_static_headers_table.hpp"
#include "log.hpp"
#include "config.hpp"
#include "application.hpp"
#include "http_client.hpp"
#include "twitter_login.hpp"
#include "poppo_id_getter.hpp"
#include "slack_login.hpp"
#include "github_login.hpp"
#include "auth_history.hpp"
#include "https_session_socket.hpp"


namespace poppo {
namespace auth_gateway {

namespace util = neosystem::util;
namespace http = neosystem::http;
namespace http2 = neosystem::http2;

constexpr const uint32_t MAX_WINDOW_SIZE = 2147483647;

enum class http2_stream_state : uint8_t {
	idle,
	reserved_local,
	reserved_remote,
	open,
	half_closed_local,
	half_closed_remote,
	closed,
};

constexpr const uint8_t FRAME_BUF_TYPE_FIRST = 0x1;
constexpr const uint8_t FRAME_BUF_TYPE_LAST = 0x2;

template<typename SessionType, typename SocketType>
class http2_stream : public std::enable_shared_from_this<http2_stream<SessionType, SocketType>>, private boost::noncopyable {
private:
	using session_type = SessionType;
	using socket_type = SocketType;
	using self_type = http2_stream<session_type, socket_type>;
	using ptr_type = std::shared_ptr<self_type>;

	using streambuf_type = std::unique_ptr<boost::asio::streambuf>;
	using queue_type = std::queue<streambuf_type>;

	enum class request_type {
		proxy,
		logout,
	};

	neosystem::wg::log::logger& logger_;
	const config& conf_;

	session_type session_;

	uint32_t stream_id_;

	http2_stream_state state_;

	bool send_settings_complete_flag_;
	http::streambuf_cache::buf_type settings_buf_;
	http::streambuf_cache::buf_type ping_buf_;

	http::streambuf_cache::buf_type request_header_;
	std::size_t request_header_pad_size_;
	std::size_t header_receive_size_;
	http2::http2_request_header header_;
	std::shared_ptr<http::http_client> http_client_;

	http::streambuf_cache::buf_type data_;
	std::size_t data_pad_size_;
	std::size_t total_data_size_;

	log_object::ptr_type log_obj_;
	auth_history::ptr_type auth_history_;

	bool is_https_;
	int64_t initial_window_size_;
	int64_t remote_window_size_;
	bool header_receiving_;
	bool send_wait_buf_last_;
	http::streambuf_cache::buf_type send_wait_buf_;

	request_type request_type_;

	template<typename HeaderType>
	void response(const HeaderType& request_header) {

		is_https_ = traits::is_https<socket_type>::value;
		if (is_https_ == false) {
			is_https_ = http::is_xfp_https(request_header);
		}

		// session
		if (request_header.exists_cookie(SESSION_ID_KEY_NAME)) {
			const auto it = request_header.find_cookie(SESSION_ID_KEY_NAME);
			if (conf_.is_session_save_enabled()) {
				constexpr bool is_http11 = std::is_same<HeaderType, http::http_request_header>::value;
				auto self = std::enable_shared_from_this<self_type>::shared_from_this();
				bool result = session_->init_session_for_redis(it->second, [self, this, is_http11](void) {
					if (is_http11) {
						response_impl(session_->get_http11_request_header());
					} else {
						response_impl(header_);
					}
					return;
				});
				if (result == false) return;
			} else {
				session_->init_session(it->second);
			}
		}

		response_impl(request_header);
		return;
	}

	template<typename HeaderType>
	void response_impl(const HeaderType& request_header) {
		const std::string& request_path = request_header.get_request_path();

		std::string check_path;
		http::remove_get_parameter(request_path, check_path);

		if (check_path == conf_.get_logout_path() && request_header.get_request_method() == http::http_method_type::POST) {
			request_type_ = request_type::logout;
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
				response_503();
				return;
			}

			if (session_->get_current_session() == nullptr) {
				return;
			}
			if (conf_.get_enable_auth_history()) {
				std::string ip_addr;
				session_->get_remote_endpoint(ip_addr);
				auth_history_ = std::make_shared<auth_history>(auth_provider::TWITTER,
															   ip_addr, request_header.find_header("User-Agent"));
			}
			get_oauth1_access_token(*auth_conf, verifier_it->second, session_->get_current_session()->get_request_token());
			return;
		}

		auto oauth2_conf = conf_.get_oauth2_server_config_for_callback(check_path);
		if (oauth2_conf != nullptr) {
			std::unordered_map<std::string, std::string> m;
			http::parse_http_url(request_path, m);

			if (conf_.get_enable_auth_history()) {
				std::string ip_addr;
				session_->get_remote_endpoint(ip_addr);
				auth_history_ = std::make_shared<auth_history>(oauth2_conf->get_auth_provider(),
															   ip_addr, request_header.find_header("User-Agent"));
			}
			if (session_->get_current_session() == nullptr) {
				response_503();
				log::info(logger_)() << S_ "session is null";
				return;
			}
			std::string session_state = session_->get_current_session()->get_state();
			//log::info(logger_)() << "state: " << m["state"] << ", state(session): " << session_state;
			if (session_state != m["state"]) {
				response_503();
				log::error(logger_)() << S_ "state error";
				return;
			}
			get_oauth2_access_token(oauth2_conf, m["code"]);
			return;
		}

		auth_conf = conf_.get_oauth1_server_config(check_path);
		if (auth_conf != nullptr) {
			if (session_->is_login()) {
				redirect_to_login_success();
				return;
			}
			// 認証ページ
			session_->set_oauth1_config(auth_conf);
			start_oauth1(*auth_conf);
			return;
		}

		// oauth2ログイン
		oauth2_conf = conf_.get_oauth2_server_config(check_path);
		if (oauth2_conf != nullptr) {
			if (session_->is_login()) {
				redirect_to_login_success();
				return;
			}
			start_oauth2(*oauth2_conf);
			return;
		}

		auto proxy_conf = conf_.get_proxy_config(request_header.get_host(), check_path);
		if (proxy_conf != nullptr) {
			request_type_ = request_type::proxy;
			reply_proxy(request_header, proxy_conf);
			return;
		}

		response("404");
		return;
	}


	template<typename HeaderType>
	bool get_preflight_header(http::headers_type& headers, const proxy_config::ptr_type& proxy_conf,
							  const HeaderType& request_header, bool is_options) {
		auto cors_conf = proxy_conf->get_cors_config();

		if (is_options) {
			headers.push_back({"Content-Length", "0"});
		}
		headers.push_back({"Access-Control-Max-Age", std::to_string(cors_conf->get_max_age())});

		if (cors_conf->has_allow_methods()) {
			headers.push_back({"Access-Control-Allow-Methods", cors_conf->get_allow_methods()});
		}
		if (cors_conf->has_allow_headers()) {
			headers.push_back({"Access-Control-Allow-Headers", cors_conf->get_allow_headers()});
		}
		if (cors_conf->is_allow_credentials()) {
			headers.push_back({"Access-Control-Allow-Credentials", "true"});
		}

		std::string origin(request_header.find_header("Origin"));
		if (origin != "") {
			if (cors_conf->is_allow_origin(origin) == false) {
				return false;
			}
			headers.push_back({"Access-Control-Allow-Origin", origin});
		}
		return true;
	}

	void append_set_cookie_header_expires(std::ostream& stream) {
		auto timep = std::chrono::system_clock::now() + std::chrono::minutes(conf_.get_session_timeout_minutes());
		auto t = std::chrono::system_clock::to_time_t(timep);
		struct tm result;
		gmtime_r(&t, &result);
		stream << "Expires=" << http::to_day_name(result) << ", " << std::put_time(&result, "%d ")
			<< http::to_month(result) << std::put_time(&result, " %Y %H:%M:%S GMT");
		return;
	}

	void append_secure(std::ostream& stream) {
		if (is_https_ == false || conf_.is_enable_cookie_secure() == false) {
			return;
		}
		stream << "; Secure";
		return;
	}

	void append_set_cookie_header_csrf_token(http::headers_type& headers, const std::string& csrf_token) {
		std::stringstream stream;
		stream << conf_.get_csrf_cookie_name() << "=" << csrf_token << "; ";
		append_set_cookie_header_expires(stream);
		append_secure(stream);
		if (conf_.get_cookie_domain() != "") {
			const auto& domain = conf_.get_cookie_domain();
			stream << "; Domain=" << domain;
		}
		http::header h;
		h.name = "Set-Cookie";
		h.value = stream.str();
		headers.push_back(h);
		return;
	}

	void append_set_cookie_header_session_id(http::headers_type& headers, const std::string& session_id) {
		std::stringstream stream;
		stream << SESSION_ID_KEY_NAME << "=" << session_id << "; ";
		append_set_cookie_header_expires(stream);
		append_secure(stream);
		if (conf_.get_cookie_domain() != "") {
			const auto& domain = conf_.get_cookie_domain();
			stream << "; Domain=" << domain;
		}
		http::header h;
		h.name = "Set-Cookie";
		h.value = stream.str();
		headers.push_back(h);
		return;
	}

	void append_set_cookie_header(http::headers_type& headers, const std::string& session_id,
								  const std::string& csrf_token) {
		append_set_cookie_header_session_id(headers, session_id);
		append_set_cookie_header_csrf_token(headers, csrf_token);
		return;
	}

	void start_oauth1(const oauth1_server_config& conf) {
		auto self = std::enable_shared_from_this<self_type>::shared_from_this();

		twitter_login::ptr_type l = std::make_shared<twitter_login>(logger_, session_->get_io_context(), session_->get_streambuf_cache());

		l->start_oauth1(conf, [this, self, l](int /*http_status*/, const std::string& oauth_token) {
			if (oauth_token == "") {
				response_503();
				return;
			}

			session_->set_request_token(oauth_token);

			auto oauth1_conf = session_->get_oauth1_config();
			if (oauth1_conf == nullptr) {
				response_503();
				return;
			}

			http::headers_type headers {{"Location", oauth1_conf->get_authenticate_url() + "?oauth_token=" + oauth_token}};
			append_set_cookie_header(headers, session_->get_session_id(), session_->get_csrf_token());
			response("302", &headers);
			return;
		});
		return;
	}

	void start_oauth2(const oauth2_server_config& conf) {
		std::string callback;
		util::urlencode(conf.get_callback_url(), callback);

		std::string state;
		util::generate_oauth2_state(state);
		session_->set_state(state);

		std::stringstream s;
		s << conf.get_user_authorization_url()
			<< "?client_id=" << conf.get_client_id()
			<< "&scope=" << conf.get_scope()
			<< "&redirect_uri=" << callback
			<< "&state=" << state;

		http::headers_type headers {{"Location", s.str()}};
		append_set_cookie_header(headers, session_->get_session_id(), session_->get_csrf_token());

		response("302", &headers);
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
			logger_, conf, session_->get_io_context(), session_->get_streambuf_cache());

		auto self = std::enable_shared_from_this<self_type>::shared_from_this();
		l->login([this, self, l](int /*http_status*/, const std::string& id) {
			if (id == "") {
				response_503();
				return;
			}
			get_poppo_id(auth_provider::SLACK, id);
			return;
		}, code);
		return;
	}

	void get_oauth2_access_token_for_github(const oauth2_server_config::ptr_type& conf, const std::string& code) {
		github_login::ptr_type l = std::make_shared<github_login>(
			logger_, conf, session_->get_io_context(), session_->get_streambuf_cache());

		auto self = std::enable_shared_from_this<self_type>::shared_from_this();
		l->login([this, self, l](int /*http_status*/, const std::string& id) {
			if (id == "") {
				response_503();
				return;
			}
			get_poppo_id(auth_provider::GITHUB, id);
			return;
		}, code);
		return;
	}

	void get_poppo_id(auth_provider auth_p, const std::string& user_id) {
		auto self = std::enable_shared_from_this<self_type>::shared_from_this();
		poppo_id_getter::ptr_type getter = std::make_shared<poppo_id_getter>(
			logger_, conf_, session_->get_io_context(), session_->get_streambuf_cache());
		if (conf_.get_enable_auth_history()) {
			getter->set_auth_history(auth_history_);
			auth_history_.reset();
		}
		getter->run([this, self, getter](std::unique_ptr<boost::asio::streambuf>, const std::string& poppo_id) {
			if (poppo_id == "") {
				response_503();
				return;
			}

			session_->update_session(poppo_id);
			redirect_to_login_success();
			return;
		}, auth_p, user_id);
		return;
	}

	void redirect_to_login_page(void) {
		http::headers_type headers {{"Location", conf_.get_no_login_redirect()}};
		response("302", &headers);
		return;
	}

	void redirect_to_login_success(void) {
		http::headers_type headers {{"Location", conf_.get_login_success_redirect()}};
		append_set_cookie_header(headers, session_->get_session_id(), session_->get_csrf_token());
		response("302", &headers);
		return;
	}

	void get_oauth1_access_token(const oauth1_server_config& conf, const std::string& oauth_verifier, const std::string& oauth_token) {
		auto self = std::enable_shared_from_this<self_type>::shared_from_this();

		twitter_login::ptr_type l = std::make_shared<twitter_login>(logger_, session_->get_io_context(), session_->get_streambuf_cache());

		l->get_oauth1_access_token(conf, oauth_verifier, oauth_token, [this, self, l](int /*http_status*/, const std::string& id) {
			if (id == "") {
				response_503();
				return;
			}
			get_poppo_id(auth_provider::TWITTER, id);
			return;
		});
		return;
	}

	void send_window_update(uint32_t increment_size, uint32_t stream_id) {
		http2::http2_frame_header h((uint32_t) sizeof(uint32_t),
									(uint8_t) http2::http2_frame_type::window_update, 0x0, stream_id);

		auto frame_header_stream = session_->get_streambuf_cache().get();
		std::ostream os1(&(*frame_header_stream));
		h.write_to_stream(os1);

		uint32_t tmp = htonl(increment_size);
		os1.write((const char *) &tmp, sizeof(uint32_t));

		session_->async_write(frame_header_stream);
		return;
	}

	void send_window_update(uint32_t increment_size) {
		http2::http2_frame_header h((uint32_t) sizeof(uint32_t),
									(uint8_t) http2::http2_frame_type::window_update, 0x0, stream_id_);

		auto frame_header_stream = session_->get_streambuf_cache().get();
		std::ostream os1(&(*frame_header_stream));
		h.write_to_stream(os1);

		uint32_t tmp = htonl(increment_size);
		os1.write((const char *) &tmp, sizeof(uint32_t));

		session_->async_write(frame_header_stream);
		return;
	}

	void response_rst_stream(uint32_t error_code) {
		auto frame_header_stream = session_->get_streambuf_cache().get();
		http2::get_rst_stream_frame(*frame_header_stream, stream_id_, error_code);
		session_->async_write(frame_header_stream);
		return;
	}

	void response_goaway(uint32_t error_code) {
		auto frame_header_stream = session_->get_streambuf_cache().get();
		http2::get_goaway_frame(*frame_header_stream, stream_id_, error_code);
		if (error_code == http2::ERROR_CODE_PROTOCOL_ERROR) {
			session_->async_write_and_close(frame_header_stream);
		} else {
			session_->async_write(frame_header_stream);
		}
		session_->remove_from_map(stream_id_);
		return;
	}

	void response_ping_ack(void) {
		http2::http2_frame_header h((uint32_t) ping_buf_->size(),
									(uint8_t) http2::http2_frame_type::ping, 0x1, stream_id_);

		auto frame_header_stream = session_->get_streambuf_cache().get();
		std::ostream os1(&(*frame_header_stream));
		h.write_to_stream(os1);

		const char *p = boost::asio::buffer_cast<const char *>(ping_buf_->data());
		os1.write(p, ping_buf_->size());

		session_->async_write(frame_header_stream);
		return;
	}

	void send_settings_and_response_ack(void) {
		http2::http2_frame_header settings_header(0, (uint8_t)
										   http2::http2_frame_type::settings, 0x0, stream_id_);
		http2::http2_frame_header ack_header(0, (uint8_t)
									  http2::http2_frame_type::settings, 0x1, stream_id_);

		auto frame_header_stream = session_->get_streambuf_cache().get();
		std::ostream os(&(*frame_header_stream));
		settings_header.write_to_stream(os);
		ack_header.write_to_stream(os);

		session_->async_write(frame_header_stream);
		send_settings_complete_flag_ = true;
		return;
	}

	void response_ack(void) {
		http2::http2_frame_header h(0, (uint8_t) http2::http2_frame_type::settings, 0x1, stream_id_);

		auto frame_header_stream = session_->get_streambuf_cache().get();
		std::ostream os1(&(*frame_header_stream));
		h.write_to_stream(os1);

		session_->async_write(frame_header_stream);
		send_settings_complete_flag_ = true;
		return;
	}

	template<typename HeaderType>
	bool check_csrf_header(const HeaderType& header) {
		auto current_session = session_->get_current_session();
		if (current_session == nullptr) return false;

		std::string token = header.find_header(conf_.get_csrf_header_name());
		if (token == "") return false;

		if (token != current_session->get_csrf_token()) return false;
		return true;
	}

	template<typename HeaderType>
	void response_401(const HeaderType& request_header, const proxy_config::ptr_type& proxy_conf) {
		if (proxy_conf->has_cors_config() == false) {
			response("401");
			return;
		}
		auto cors_conf = proxy_conf->get_cors_config();
		std::string origin(request_header.find_header("Origin"));
		http::headers_type headers;
		if (origin != "") {
			if (cors_conf->is_allow_origin(origin) == false) {
				response("503");
				return;
			}
			headers.push_back({"Access-Control-Allow-Origin", origin});
		}
		if (cors_conf->has_allow_methods()) {
			headers.push_back({"Access-Control-Allow-Methods", cors_conf->get_allow_methods()});
		}
		if (cors_conf->has_allow_headers()) {
			headers.push_back({"Access-Control-Allow-Headers", cors_conf->get_allow_headers()});
		}
		if (cors_conf->is_allow_credentials()) {
			headers.push_back({"Access-Control-Allow-Credentials", "true"});
		}
		response("401", &headers);
		return;
	}

	template<typename HeaderType>
	void reply_proxy_with_auth(const HeaderType& request_header, const proxy_config::ptr_type& proxy_conf) {
		auto current_session = session_->get_current_session();
		if (current_session == nullptr || current_session->get_poppo_id() == "") {
			// ログインしてない
			if (proxy_conf->has_cors_config() && request_header.get_request_method() == http::http_method_type::OPTIONS) {
				// CORS
				http::headers_type cors_headers;
				if (get_preflight_header(cors_headers, proxy_conf, request_header, true) == false) {
					response_503();
					return;
				}
				response("200", &cors_headers);
				return;
			}

			// まだログインしてない
			if (proxy_conf->is_response_401()) {
				response_401(request_header, proxy_conf);
				return;
			}

			redirect_to_login_page();
			return;
		}

		http::headers_type additional_header {{"X-POPPO-ID", current_session->get_poppo_id()}};
		reply_proxy_impl(request_header, proxy_conf, false, &additional_header);
		return;
	}

	template<typename HeaderType>
	void reply_proxy_impl(const HeaderType& request_header, const proxy_config::ptr_type& proxy_conf,
						  bool append_poppo_id_if_exist,
						  const http::headers_type *additional_headers = nullptr) {

		std::shared_ptr<http::headers_type> cors_headers_ptr;
		if (proxy_conf->has_cors_config()) {
			auto cors_conf = proxy_conf->get_cors_config();

			if (request_header.get_request_method() == http::http_method_type::OPTIONS) {
				// CORS
				http::headers_type cors_headers;
				if (get_preflight_header(cors_headers, proxy_conf, request_header, true) == false) {
					response_503();
					return;
				}
				response("200", &cors_headers);
				return;
			}

			// CORS
			cors_headers_ptr = std::make_shared<http::headers_type>();
			if (get_preflight_header(*cors_headers_ptr, proxy_conf, request_header, false) == false) {
				response_503();
				return;
			}
		}

		auto self = std::enable_shared_from_this<self_type>::shared_from_this();
		http_client_ = http::http_client::create(logger_, session_->get_io_context(), session_->get_streambuf_cache(), [self, this, cors_headers_ptr](
				uint8_t flag_type, const http::http_client_status& client_status, const http::http_response_header& header,
				const char *p, size_t size) {
			if (client_status && size == 0 && flag_type & (uint8_t) http::http_client::callback_flag_type::first) {
				response_503();
				http_client_.reset();
				log::error(logger_)() << S_ << "error: " << client_status;
				return;
			}
			if (flag_type & (uint8_t) http::http_client::callback_flag_type::last) {
				if (flag_type & (uint8_t) http::http_client::callback_flag_type::first) {
					if (cors_headers_ptr == nullptr) {
						response_header_and_body(header, nullptr, true, p, size);
					} else {
						response_header_and_body(header, &(*cors_headers_ptr), true, p, size);
					}
				} else {
					response_body(true, p, size);
				}
				http_client_.reset();
				return;
			}
			if (flag_type & (uint8_t) http::http_client::callback_flag_type::first) {
				// CORS
				if (cors_headers_ptr == nullptr) {
					response_header_and_body(header, nullptr, false, p, size);
				} else {
					response_header_and_body(header, &(*cors_headers_ptr), false, p, size);
				}
			} else {
				if (p != nullptr && size > 0) {
					response_body(false, p, size);
				}
			}
			return;
		});

		auto buf = session_->get_streambuf_cache().get();
		std::ostream stream(&(*buf));

		const auto& host = proxy_conf->get_host();
		const auto& port = proxy_conf->get_port();

		if (proxy_conf->get_path() != "") {
			std::string new_request_path;
			replace_path(proxy_conf, proxy_conf->get_request_path(), proxy_conf->get_path(), request_header.get_request_path(), new_request_path);
			stream << request_header.get_request_method_as_str() << " " << new_request_path << " HTTP/1.1\r\n";
			//log::debug(logger_)() << "start http request (" << request_header.get_request_method_as_str() << " " << new_request_path << " HTTP/1.1" << ")";
		} else {
			stream << request_header.get_request_method_as_str() << " " << request_header.get_request_path() <<  " HTTP/1.1\r\n";
			//log::debug(logger_)() << "start http request (" << request_header.get_request_method_as_str() << " " << request_header.get_request_path() << " HTTP/1.1" << ")";
		}

		stream << "Host: " << host << ":" << port << "\r\n";
		if (additional_headers != nullptr) {
			for (const auto& h : *additional_headers) {
				stream << h.name << ": " << h.value << "\r\n";
			}
		}
		if (append_poppo_id_if_exist) {
			auto current_session = session_->get_current_session();
			if (current_session != nullptr && current_session->get_poppo_id() != "") {
				// poppo IDをリクエストに追加
				stream << "X-POPPO-ID: " << current_session->get_poppo_id() << "\r\n";
			}
		}
		write_request_header(request_header, stream);
		stream << "\r\n";

		http_client_->start(host.c_str(), port.c_str(), buf);
		return;
	}

	void replace_path(const proxy_config::ptr_type& proxy_conf, const std::string& config_request_path,
			const std::string& config_path, const std::string& request_path, std::string& new_request_path) {
		new_request_path = config_path;
		//if (config_path[config_path.size() - 1] != '/') {
		//	new_request_path += '/';
		//}

		new_request_path += (request_path.c_str() + config_request_path.size());

		if (proxy_conf->need_replace_poppo_id() && session_->get_current_session() != nullptr) {
			new_request_path.replace(proxy_conf->get_replace_pos(), 10, session_->get_current_session()->get_poppo_id());
		}
		if (new_request_path == "") {
			new_request_path = "/";
		}
		return;
	}

	template<typename HeaderType>
	void reply_proxy(const HeaderType& request_header, const proxy_config::ptr_type& proxy_conf) {

		if (proxy_conf->need_csrf_check() && http::need_csrf_check(request_header)) {
			if (check_csrf_header(request_header) == false) {
				response("400");
				return;
			}
		}
		if (proxy_conf->need_auth() != false) {
			// 認証
			reply_proxy_with_auth(request_header, proxy_conf);
			return;
		}

		reply_proxy_impl(request_header, proxy_conf, true);
		return;
	}

	template<typename HeaderType>
	void write_request_header(const HeaderType& request_header, std::ostream& os) {
		const auto& headers = request_header.get_headers();
		for (const auto& h : headers) {
			if (strcasecmp("Host", h.name.c_str()) == 0) {
				continue;
			}
			if (strcasecmp("HTTP2-Settings", h.name.c_str()) == 0) {
				continue;
			}
			if (strcasecmp("Upgrade", h.name.c_str()) == 0) {
				continue;
			}
			if (strcasecmp("Connection", h.name.c_str()) == 0) {
				continue;
			}
			os << h.name << ": " << h.value << "\r\n";
		}
		return;
	}

	void add_additional_http2_header(const http::headers_type& additional_headers, std::ostream& os) {
		for (const auto& h : additional_headers) {
			if (strcasecmp(h.name.c_str(), "Transfer-Encoding") == 0) {
				continue;
			} else if (strcasecmp(h.name.c_str(), "Connection") == 0) {
				continue;
			} else if (strcasecmp(h.name.c_str(), "Keep-Alive") == 0) {
				continue;
			}
			http2::write_http2_header2(os, h.name, h.value);
		}
		return;
	}

	void http11_header_to_http2_header(const http::http_response_header& http11_header, std::ostream& os) {
		const auto& header = http11_header.get_headers();

		for (const auto& h : header) {
			if (strcasecmp(h.name.c_str(), "Transfer-Encoding") == 0) {
				continue;
			} else if (strcasecmp(h.name.c_str(), "Connection") == 0) {
				continue;
			} else if (strcasecmp(h.name.c_str(), "Keep-Alive") == 0) {
				continue;
			}
			http2::write_http2_header2(os, h.name, h.value);
		}
		return;
	}

	void response_403(void) {
		response("403");
		return;
	}

	void response_503(void) {
		response("503");
		return;
	}

	void response(const char *status, const http::headers_type *response_headers = nullptr) {
		auto response_stream = session_->get_streambuf_cache().get();
		std::ostream os(&(*response_stream));
		http2::write_http2_header2(os, ":status", status);

		if (response_headers != nullptr) {
			for (const auto& h : *response_headers) {
				http2::write_http2_header2(os, h.name, h.value);
			}
		}

		const std::size_t max_frame_size = (std::size_t) session_->get_settings().get_max_frame_size();

		std::size_t remain_size = response_stream->size();
		const char *p = boost::asio::buffer_cast<const char *>(response_stream->data());
		std::size_t send_size;
		uint8_t flags = (uint8_t) http2::http2_frame_flags::end_stream;
		bool is_first = true;
		for (; ; ) {
			if (remain_size <= max_frame_size) {
				flags |= (uint8_t) http2::http2_frame_flags::end_headers;
				send_size = remain_size;
			} else {
				send_size = max_frame_size;
			}
			response_header_impl(flags, p, send_size, is_first);
			is_first = false;
			if (flags & 0x4) {
				break;
			}
			remain_size -= send_size;
			p += send_size;
		}
		// access log
		if (log_obj_ != nullptr) {
			log_obj_->set_http_status(status);
			log_obj_->set_request_complete_time();
			application::access_log(log_obj_);
			log_obj_.reset();
		}
		return;
	}

	void response_header_and_body(const http::http_response_header& http11_header, const http::headers_type *additional_headers,
								  bool is_last, const char *body, size_t body_size) {
		auto response_stream = session_->get_streambuf_cache().get();
		std::ostream os(&(*response_stream));
		http2::write_http2_header(os, ":status", http11_header.get_status_code_str().c_str());

		http11_header_to_http2_header(http11_header, os);
		if (additional_headers != nullptr) {
			add_additional_http2_header(*additional_headers, os);
		}

		const std::size_t max_frame_size = (std::size_t) session_->get_settings().get_max_frame_size();

		auto response_stream1 = session_->get_streambuf_cache().get();
		std::ostream os1(&(*response_stream1));

		std::size_t remain_size = response_stream->size();
		response_stream1->prepare(body_size + 9 + remain_size + 9);
		const char *p = boost::asio::buffer_cast<const char *>(response_stream->data());
		std::size_t send_size;
		uint8_t flags = 0x0;
		bool is_first = true;
		for (; ; ) {
			if (remain_size <= max_frame_size) {
				if (is_last && body_size <= 0) {
					flags = 0x4 | 0x1;
				} else {
					flags = 0x4;
				}
				send_size = remain_size;
			} else {
				send_size = max_frame_size;
			}
			response_header_impl(flags, p, send_size, os1, is_first);
			is_first = false;
			if (flags & 0x4) {
				break;
			}
			remain_size -= send_size;
			p += send_size;
		}
		// access log
		if (log_obj_ != nullptr) {
			log_obj_->set_http_status(http11_header.get_status_code_str().c_str());
			log_obj_->set_request_complete_time();
			application::access_log(log_obj_);
			log_obj_.reset();
		}
		if (body != nullptr && body_size > 0) {
			response_body(is_last, body, body_size, os1);
		}
		session_->async_write(response_stream1);
		return;
	}

	void response_header_impl(uint8_t flags, const char *p, size_t size, std::ostream& os1, bool is_first) {
		const uint8_t frame_type = (uint8_t) ((is_first) ?
											  http2::http2_frame_type::headers : http2::http2_frame_type::continuation);
		http2::http2_frame_header h((uint32_t) size, frame_type, flags, stream_id_);
		h.write_to_stream(os1);
		os1.write(p, size);
		return;
	}

	void response_header(const http::http_response_header& http11_header,
						 const http::headers_type *additional_headers = nullptr) {
		auto response_stream = session_->get_streambuf_cache().get();
		std::ostream os(&(*response_stream));
		http2::write_http2_header(os, ":status", http11_header.get_status_code_str().c_str());

		http11_header_to_http2_header(http11_header, os);
		if (additional_headers != nullptr) {
			add_additional_http2_header(*additional_headers, os);
		}

		const std::size_t max_frame_size = (std::size_t) session_->get_settings().get_max_frame_size();

		std::size_t remain_size = response_stream->size();
		const char *p = boost::asio::buffer_cast<const char *>(response_stream->data());
		std::size_t send_size;
		uint8_t flags = 0x0;
		bool is_first = true;
		for (; ; ) {
			if (remain_size <= max_frame_size) {
				flags = 0x4;
				send_size = remain_size;
			} else {
				send_size = max_frame_size;
			}
			response_header_impl(flags, p, send_size, is_first);
			is_first = false;
			if (flags & 0x4) {
				break;
			}
			remain_size -= send_size;
			p += send_size;
		}
		// access log
		if (log_obj_ != nullptr) {
			log_obj_->set_http_status(http11_header.get_status_code_str().c_str());
			log_obj_->set_request_complete_time();
			application::access_log(log_obj_);
		}
		return;
	}

	void response_header_impl(uint8_t flags, const char *p, size_t size, bool is_first) {
		const uint8_t frame_type = (uint8_t) ((is_first) ?
											  http2::http2_frame_type::headers : http2::http2_frame_type::continuation);
		http2::http2_frame_header h((uint32_t) size, frame_type, flags, stream_id_);
		auto frame_header_stream = session_->get_streambuf_cache().get();
		std::ostream os1(&(*frame_header_stream));
		h.write_to_stream(os1);
		os1.write(p, size);

		session_->async_write(frame_header_stream);
		return;
	}

	void append_send_wait_buf(const char *p, size_t size) {
		if (send_wait_buf_ == nullptr) {
			send_wait_buf_last_ = false;
			send_wait_buf_ = session_->get_streambuf_cache().get();
		}
		std::ostream os(&(*send_wait_buf_));
		if (p != nullptr && size > 0) {
			os.write(p, size);
		}
		return;
	}

	void response_body(bool is_last, const char *p, size_t size, std::ostream& os2) {
		if (send_wait_buf_ != nullptr) {
			append_send_wait_buf(p, size);
			send_wait_buf_last_ = is_last;

			const char *wait_buf = boost::asio::buffer_cast<const char *>(send_wait_buf_->data());
			std::size_t consume_size = response_body_impl(is_last, wait_buf, send_wait_buf_->size(), os2, true);
			send_wait_buf_->consume(consume_size);
			if (send_wait_buf_->size() <= 0) {
				session_->get_streambuf_cache().release(send_wait_buf_);
			}
			return;
		}
		response_body_impl(is_last, p, size, os2, false);
		return;
	}

	void response_body(bool is_last, const char *p, size_t size) {
		if (send_wait_buf_ != nullptr) {
			append_send_wait_buf(p, size);
			send_wait_buf_last_ = is_last;

			const char *wait_buf = boost::asio::buffer_cast<const char *>(send_wait_buf_->data());
			std::size_t consume_size = response_body_impl(is_last, wait_buf, send_wait_buf_->size(), true);
			send_wait_buf_->consume(consume_size);
			if (send_wait_buf_->size() <= 0) {
				session_->get_streambuf_cache().release(send_wait_buf_);
			}
			return;
		}
		response_body_impl(is_last, p, size, false);
		return;
	}

	std::size_t response_body_impl(bool is_last, const char *p, std::size_t size, std::ostream& os2, bool is_wait_buf) {
		const std::size_t max_frame_size = (std::size_t) session_->get_settings().get_max_frame_size();
		std::size_t send_size = (size <= max_frame_size) ? size : max_frame_size;

		send_size = session_->update_send_size(send_size, remote_window_size_);
		remote_window_size_ -= send_size;

		if (p != nullptr && size > 0 && send_size <= 0) {
			if (is_wait_buf == false) {
				append_send_wait_buf(p, size);
			}
			return 0;
		}

		uint8_t flags = 0x0;
		if (is_last && size <= send_size) {
			flags = (uint8_t) http2::http2_frame_flags::end_stream;
			session_->remove_from_map(stream_id_);
		}
		http2::http2_frame_header h2((uint32_t) send_size,
							 (uint8_t) http2::http2_frame_type::data, flags, stream_id_);
		h2.write_to_stream(os2);
		if (p != nullptr && send_size > 0) {
			os2.write(p, send_size);
		}

		if (send_size < size) {
			return response_body_impl(is_last, p + send_size, size - send_size, os2, is_wait_buf) + send_size;
		}
		return send_size;
	}

	std::size_t response_body_impl(bool is_last, const char *p, size_t size, bool is_wait_buf) {
		const std::size_t max_frame_size = (std::size_t) session_->get_settings().get_max_frame_size();
		std::size_t send_size = (size <= max_frame_size) ? size : max_frame_size;

		send_size = session_->update_send_size(send_size, remote_window_size_);
		remote_window_size_ -= send_size;

		if (p != nullptr && size > 0 && send_size <= 0) {
			if (is_wait_buf == false) {
				append_send_wait_buf(p, size);
			}
			return 0;
		}

		uint8_t flags = 0x0;
		if (is_last && size <= send_size) {
			flags = (uint8_t) http2::http2_frame_flags::end_stream;
			session_->remove_from_map(stream_id_);
		}
		http2::http2_frame_header h2((uint32_t) send_size,
							 (uint8_t) http2::http2_frame_type::data, flags, stream_id_);
		auto frame_header_stream = session_->get_streambuf_cache().get();
		std::ostream os2(&(*frame_header_stream));
		h2.write_to_stream(os2);
		if (p != nullptr && send_size > 0) {
			os2.write(p, send_size);
		}

		session_->async_write(frame_header_stream);

		if (send_size < size) {
			return response_body_impl(is_last, p + send_size, size - send_size, is_wait_buf) + send_size;
		}
		return send_size;
	}

	bool response_priority_frame(http::streambuf_cache::buf_type& buf, std::size_t buf_size, uint8_t buf_type1) {
		if (stream_id_ == 0) {
			response_goaway(http2::ERROR_CODE_PROTOCOL_ERROR);
			return false;
		}
		if (data_ == nullptr) {
			data_ = session_->get_streambuf_cache().get();
		}
		const char *p = boost::asio::buffer_cast<const char *>(buf->data());
		std::ostream os(&(*data_));
		os.write(p, buf_size);
		if (!(buf_type1 & FRAME_BUF_TYPE_LAST)) {
			return true;
		}
		if (data_->size() != 5) {
			response_goaway(http2::ERROR_CODE_FRAME_SIZE_ERROR);
			session_->get_streambuf_cache().release(data_);
			return false;
		}
		const uint8_t *priority_buf = boost::asio::buffer_cast<const uint8_t *>(data_->data());
		uint32_t stream_dependency = ntohl(*((const uint32_t *) priority_buf)) & 0x7FFFFFFF;
		session_->get_streambuf_cache().release(data_);
		if (stream_dependency == stream_id_) {
			response_goaway(http2::ERROR_CODE_PROTOCOL_ERROR);
			return false;
		}
		return true;
	}

	bool response_ping_frame(http::streambuf_cache::buf_type& buf, std::size_t buf_size,
							 uint8_t buf_type1, const http2::http2_frame_header& header) {
		if (stream_id_ != 0) {
			log::info(logger_)() << "Invalid stream id: " << stream_id_;
			response_goaway(http2::ERROR_CODE_PROTOCOL_ERROR);
			return false;
		}
		if (header.get_length() != 8) {
			response_goaway(http2::ERROR_CODE_FRAME_SIZE_ERROR);
			return false;
		}
		const uint8_t flags = header.get_flags();
		if (flags == 0x1) {
			// ACK
			return true;
		}

		if (ping_buf_ == nullptr) {
			ping_buf_ = session_->get_streambuf_cache().get();
		}
		const char *p = boost::asio::buffer_cast<const char *>(buf->data());
		if (buf_size > 0) {
			std::ostream os(&(*ping_buf_));
			os.write(p, buf_size);
		}

		if (!(buf_type1 & FRAME_BUF_TYPE_LAST)) {
			return true;
		}
		response_ping_ack();
		session_->get_streambuf_cache().release(ping_buf_);
		return true;
	}

	bool response_header_frame(http::streambuf_cache::buf_type& buf, std::size_t buf_size,
							   uint8_t buf_type1, const http2::http2_frame_header& header) {
		if (stream_id_ == 0) {
			response_goaway(http2::ERROR_CODE_PROTOCOL_ERROR);
			return false;
		}
		if (state_ == http2_stream_state::closed) {
			response_goaway(http2::ERROR_CODE_STREAM_CLOSED);
			return false;
		}
		const uint8_t type = header.get_type();
		const uint8_t flags = header.get_flags();
		if (type == (uint8_t) http2::http2_frame_type::headers && state_ == http2_stream_state::half_closed_remote) {
			response_goaway(http2::ERROR_CODE_STREAM_CLOSED);
			return false;
		}
		if (type == (uint8_t) http2::http2_frame_type::headers && state_ == http2_stream_state::open
			&& !(flags & (uint8_t) http2::http2_frame_flags::end_stream)) {
			response_goaway(http2::ERROR_CODE_PROTOCOL_ERROR);
			return false;
		}
		if (header_receiving_ == false && type == (uint8_t) http2::http2_frame_type::continuation) {
			response_goaway(http2::ERROR_CODE_PROTOCOL_ERROR);
			return false;
		}
		if (request_header_ == nullptr) {
			if (session_->start_header_receive(stream_id_) == false) {
				response_goaway(http2::ERROR_CODE_PROTOCOL_ERROR);
				return false;
			}
			header_receive_size_ = 0;
			request_header_ = session_->get_streambuf_cache().get();
			header_receiving_ = true;
			state_ = http2_stream_state::open;
			session_->set_max_stream_id(stream_id_);
		}

		std::ostream os(&(*request_header_));
		const char *p = boost::asio::buffer_cast<const char *>(buf->data());
		if (buf_type1 & FRAME_BUF_TYPE_FIRST) {
			if (flags & (uint8_t) http2::http2_frame_flags::padded) {
				uint8_t pad_size = (uint8_t) *p;
				buf_size -= 1;
				p += 1;
				request_header_pad_size_ = pad_size;
				if (header.get_length() <= pad_size) {
					response_goaway(http2::ERROR_CODE_PROTOCOL_ERROR);
					return false;
				}
			} else {
				request_header_pad_size_ = 0;
			}
		}
		std::size_t need_size = header.get_length() - ((request_header_pad_size_ == 0) ? 0 : request_header_pad_size_ + 1);
		std::size_t after_size = buf_size + header_receive_size_;
		if (after_size > need_size) {
			if (need_size <= header_receive_size_) {
				buf_size = 0;
			} else {
				buf_size = need_size - header_receive_size_;
			}
		}
		if (buf_size > 0) {
			os.write(p, buf_size);
			if (buf_type1 & FRAME_BUF_TYPE_LAST) {
				header_receive_size_ = 0;
			} else {
				header_receive_size_ += buf_size;
			}
		}

		if (!(buf_type1 & FRAME_BUF_TYPE_LAST)) {
			return true;
		}

		if (flags & (uint8_t) http2::http2_frame_flags::end_headers) {
			session_->end_header_receive();
			header_receiving_ = false;

			const uint8_t *header_buf = boost::asio::buffer_cast<const uint8_t *>(request_header_->data());
			std::size_t header_length = request_header_->size();
			if (flags & (uint8_t) http2::http2_frame_flags::priority) {
				if (header_length < 5) {
					response_goaway(http2::ERROR_CODE_COMPRESSION_ERROR);
					return false;
				}
				uint32_t stream_dependency = ntohl(*((const uint32_t *) header_buf)) & 0x7FFFFFFF;
				if (stream_dependency == stream_id_) {
					response_goaway(http2::ERROR_CODE_PROTOCOL_ERROR);
					return false;
				}
				header_buf += 5;
				header_length -= 5;
			}

			uint32_t parse_result = header_.parse(header_buf, header_length, session_->get_headers_table(),
												  session_->get_settings().get_header_table_size());
			session_->get_streambuf_cache().release(request_header_);

			if (parse_result != 0) {
				log::error(logger_)() << S_ << "parse error";
				// goaway
				response_goaway(parse_result);
				return false;
			}
			log_obj_ = log_object::create(header_);
			log_obj_->set_request_start_time();
			response(header_);
		}
		if (flags & (uint8_t) http2::http2_frame_flags::end_stream) {
			state_ = http2_stream_state::half_closed_remote;
		}
		return true;
	}

	bool response_window_update_frame(http::streambuf_cache::buf_type& buf,
									  std::size_t buf_size, uint8_t buf_type1) {
		if (data_ == nullptr) {
			data_ = session_->get_streambuf_cache().get();
		}

		const char *p = boost::asio::buffer_cast<const char *>(buf->data());
		if (buf_size > 0) {
			std::ostream os(&(*data_));
			os.write(p, buf_size);
		}
		if (!(buf_type1 & FRAME_BUF_TYPE_LAST)) {
			return true;
		}
		const uint8_t *window_update_buf = boost::asio::buffer_cast<const uint8_t *>(data_->data());
		int32_t window_size = ntohl(*((const int32_t *) window_update_buf)) & 0x7FFFFFFF;
		session_->get_streambuf_cache().release(data_);
		//log::debug(logger_)() << "window_size: " << window_size;
		if (window_size == 0) {
			response_goaway(http2::ERROR_CODE_PROTOCOL_ERROR);
			return false;
		}
		if (stream_id_ == 0) {
			if (session_->update_window_size(window_size) == false) {
				response_goaway(http2::ERROR_CODE_FLOW_CONTROL_ERROR);
			}
		} else {
			remote_window_size_ += window_size;
			//log::debug(logger_)() << "window_size: " << window_size << ", remote_window_size_: " << remote_window_size_;
			if (remote_window_size_ > MAX_WINDOW_SIZE) {
				log::error(logger_)() << S_ << "remote_window_size_ > MAX_WINDOW_SIZE";
				response_rst_stream(http2::ERROR_CODE_FLOW_CONTROL_ERROR);
				return true;
			}
			response_send_wait_buf();
		}
		return true;
	}

	bool response_data_frame(http::streambuf_cache::buf_type& buf, std::size_t buf_size,
							 uint8_t buf_type1, const http2::http2_frame_header& header) {
		if (data_ == nullptr) {
			data_ = session_->get_streambuf_cache().get();
		}

		const char *p = boost::asio::buffer_cast<const char *>(buf->data());
		const uint8_t flags = header.get_flags();
		if (buf_type1 & FRAME_BUF_TYPE_FIRST) {
			if (flags & (uint8_t) http2::http2_frame_flags::padded) {
				uint8_t pad_size = (uint8_t) *p;
				buf_size -= 1;
				p += 1;
				data_pad_size_ = pad_size;
				if (header.get_length() <= pad_size) {
					response_goaway(http2::ERROR_CODE_PROTOCOL_ERROR);
					return false;
				}
			} else {
				data_pad_size_ = 0;
			}
		}
		std::size_t need_size = header.get_length() - ((data_pad_size_ == 0) ? 0 : data_pad_size_ + 1);
		//log::info(logger_)() << S_ << "pad_size: " << data_pad_size_ << ", size: " << data_->size() << ", need_size: " << need_size;
		std::size_t after_size = buf_size + data_->size();
		if (after_size > need_size) {
			if (need_size <= data_->size()) {
				buf_size = 0;
			} else {
				buf_size = need_size - data_->size();
			}
		}
		if (buf_size > 0) {
			std::ostream os(&(*data_));
			os.write(p, buf_size);
		}
		if (!(buf_type1 & FRAME_BUF_TYPE_LAST)) {
			return true;
		}
		if (request_type_ != request_type::logout) {
			if (http_client_ != nullptr && data_->size() > 0) {
				if (data_pad_size_ == 0) {
					need_size = data_->size();
				} else {
					need_size = data_->size() + data_pad_size_ + 1;
				}
				if (need_size != header.get_length()) {
					log::error(logger_)() << S_ << "error (pad_size: " << data_pad_size_ << ", size: " << data_->size() << ", length: " << header.get_length() << ")";
					response_goaway(http2::ERROR_CODE_PROTOCOL_ERROR);
					return false;
				}
				std::size_t write_size = data_->size();
				total_data_size_ += write_size;
				http_client_->async_write(data_);
			}
			session_->get_streambuf_cache().release(data_);
		}
		// TODO
		send_window_update(3 * 1024 * 1024, 0);
		send_window_update(3 * 1024 * 1024);

		if (flags & (uint8_t) http2::http2_frame_flags::end_stream) {
			state_ = http2_stream_state::half_closed_remote;
			if (header_.get_content_length() > 0 && header_.get_content_length() != total_data_size_) {
				log::error(logger_)() << S_ << "invalid size (total: " << total_data_size_ << ", content-lentgh: " << header_.get_content_length() << ")";
				response_goaway(http2::ERROR_CODE_PROTOCOL_ERROR);
				return false;
			}
			if (request_type_ == request_type::logout) {
				handle_request_logout(*data_);
				session_->get_streambuf_cache().release(data_);
			}
		}
		return true;
	}

	void handle_request_logout(const boost::asio::streambuf& buf) {
		auto current_session = session_->get_current_session();
		if (current_session == nullptr) {
			log::info(logger_)() << S_ << "Invalid logout request";
			redirect_to_login_page();
			return;
		}

		std::string request_string(boost::asio::buffer_cast<const char *>(buf.data()), buf.size());
		std::unordered_map<std::string, std::string> result;

		http::parse_http_post(request_string, result);
		auto it = result.find(POST_CSRF_TOKEN_NAME);
		if (it == result.end()) {
			log::info(logger_)() << S_ << "Invalid logout request";
			response_403();
			return;
		}
		if (it->second != current_session->get_csrf_token()) {
			log::info(logger_)() << S_ << "Invalid logout request  " << it->second << ", " << current_session->get_csrf_token();
			response_403();
			return;
		}

		session_->logout();

		redirect_to_login_page();
		return;
	}

public:
	http2_stream(session_type session, uint32_t stream_id) :
		logger_(application::get_logger()),
		conf_(application::get_config()),
		session_(session),
		stream_id_(stream_id),
		state_(http2_stream_state::idle),
		send_settings_complete_flag_(false),
		total_data_size_(0),
		header_receiving_(false) {

		initial_window_size_ = remote_window_size_ = session_->get_settings().get_initial_window_size();
	}

	//~http2_stream(void) {
	//	neosystem::wg::log::info(logger_)() << S_ << "http2_stream destruct (stream_id_: " << stream_id_ << ")";
	//}

	bool send_buffer(http::streambuf_cache::buf_type& buf, std::size_t buf_size, uint8_t buf_type1,
					 const http2::http2_frame_header& header) {

		if (header.get_length() > session_->get_settings().get_max_frame_size()) {
			response_goaway(http2::ERROR_CODE_FRAME_SIZE_ERROR);
			return false;
		}

		const uint8_t type = header.get_type();
		if (type != (uint8_t) http2::http2_frame_type::headers &&
			type != (uint8_t) http2::http2_frame_type::continuation) {
			if (session_->is_header_receiving()) {
				response_goaway(http2::ERROR_CODE_PROTOCOL_ERROR);
				return false;
			}
		}
		if (type == (uint8_t) http2::http2_frame_type::ping && stream_id_ != 0) {
			response_goaway(http2::ERROR_CODE_PROTOCOL_ERROR);
			return false;
		}

		if (type == (uint8_t) http2::http2_frame_type::settings) {
			if (stream_id_ != 0) {
				response_goaway(http2::ERROR_CODE_PROTOCOL_ERROR);
				return false;
			}
			state_ = http2_stream_state::open;
			const uint8_t flags = header.get_flags();
			if (flags & 0x1) {
				// ACK
				if (header.get_length() != 0) {
					response_goaway(http2::ERROR_CODE_FRAME_SIZE_ERROR);
					return false;
				}
				return true;
			}

			if (buf_size > 0) {
				if (settings_buf_ == nullptr) {
					settings_buf_ = session_->get_streambuf_cache().get();
				}
				std::ostream os(&(*settings_buf_));
				const char *p = boost::asio::buffer_cast<const char *>(buf->data());
				os.write(p, buf_size);
			}

			if (!(buf_type1 & FRAME_BUF_TYPE_LAST)) {
				return true;
			}

			if (settings_buf_ != nullptr) {
				uint32_t error_code = session_->init_settings(*settings_buf_);
				if (error_code != 0) {
					response_goaway(error_code);
					return false;
				}
				session_->get_streambuf_cache().release(settings_buf_);
			}

			if (send_settings_complete_flag_ == false) {
				send_settings_and_response_ack();
			} else {
				response_ack();
			}
			return true;
		} else if (type == (uint8_t) http2::http2_frame_type::rst_stream) {
			if (stream_id_ == 0 || state_ == http2_stream_state::idle) {
				response_goaway(http2::ERROR_CODE_PROTOCOL_ERROR);
				return false;
			}
			if (header.get_length() != 4) {
				response_goaway(http2::ERROR_CODE_FRAME_SIZE_ERROR);
				return false;
			}
			state_ = http2_stream_state::closed;
			session_->remove_from_map(stream_id_);
		} else if (type == (uint8_t) http2::http2_frame_type::window_update) {
			if (state_ == http2_stream_state::idle) {
				response_goaway(http2::ERROR_CODE_PROTOCOL_ERROR);
				return false;
			}
			if (header.get_length() != 4) {
				response_goaway(http2::ERROR_CODE_FRAME_SIZE_ERROR);
				return false;
			}
			return response_window_update_frame(buf, buf_size, buf_type1);
		} else if (type == (uint8_t) http2::http2_frame_type::priority) {
			if (header.get_length() != 5) {
				response_goaway(http2::ERROR_CODE_FRAME_SIZE_ERROR);
				return false;
			}
			return response_priority_frame(buf, buf_size, buf_type1);
		} else if (type == (uint8_t) http2::http2_frame_type::ping) {
			return response_ping_frame(buf, buf_size, buf_type1, header);
		} else if (type == (uint8_t) http2::http2_frame_type::goaway) {
			if (stream_id_ != 0) {
				response_goaway(http2::ERROR_CODE_PROTOCOL_ERROR);
				return false;
			}
			log::info(logger_)() << S_ << "goaway";
			//session_->socket_shutdown();
			return true;
		} else if (type == (uint8_t) http2::http2_frame_type::data) {
			if (state_ == http2_stream_state::idle) {
				response_goaway(http2::ERROR_CODE_PROTOCOL_ERROR);
				return false;
			}
			if (state_ != http2_stream_state::open && state_ != http2_stream_state::half_closed_local) {
				response_goaway(http2::ERROR_CODE_STREAM_CLOSED);
				return false;
			}
			if (stream_id_ == 0) {
				response_goaway(http2::ERROR_CODE_PROTOCOL_ERROR);
				return false;
			}
			return response_data_frame(buf, buf_size, buf_type1, header);
		} else if (type == (uint8_t) http2::http2_frame_type::headers || type == (uint8_t) http2::http2_frame_type::continuation) {
			return response_header_frame(buf, buf_size, buf_type1, header);
		} else if (type == (uint8_t) http2::http2_frame_type::push_promise) {
			response_goaway(http2::ERROR_CODE_PROTOCOL_ERROR);
			return false;
		} else {
			neosystem::wg::log::error(logger_)() << S_ << "Unexpected frame: " << ((uint32_t) type);
		}
		return true;
	}

	void send_settings(void) {
		http2::http2_frame_header h(0, (uint8_t) http2::http2_frame_type::settings,
									0x0, stream_id_);

		auto frame_header_stream = session_->get_streambuf_cache().get();
		std::ostream os1(&(*frame_header_stream));
		h.write_to_stream(os1);

		session_->async_write(frame_header_stream);
		return;
	}

	void response(const log_object::ptr_type& log_obj, const http::http_request_header& request_header) {
		log_obj_ = log_obj;
		if (log_obj_ != nullptr) {
			log_obj_->set_request_start_time();
		}
		response(request_header);
		return;
	}

	http2_stream_state get_state(void) const {
		return state_;
	}

	void response_send_wait_buf(void) {
		if (send_wait_buf_ == nullptr) {
			return;
		}
		const char *wait_buf = boost::asio::buffer_cast<const char *>(send_wait_buf_->data());
		std::size_t consume_size = response_body_impl(send_wait_buf_last_, wait_buf, send_wait_buf_->size(), true);
		send_wait_buf_->consume(consume_size);
		if (send_wait_buf_->size() <= 0) {
			session_->get_streambuf_cache().release(send_wait_buf_);
		}
		return;
	}

	void update_init_window_size(int32_t w) {
		remote_window_size_ += w - initial_window_size_;
		initial_window_size_ = w;
		return;
	}
};

}
}

#endif
