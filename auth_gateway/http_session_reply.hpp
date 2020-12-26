#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_HTTP_SESSION_REPLY_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_HTTP_SESSION_REPLY_HPP_

#include <sstream>
#include <chrono>
#include <ctime>
#include <iomanip>

#include "http_request_header.hpp"
#include "application.hpp"
#include "http_common.hpp"


namespace poppo {
namespace auth_gateway {

namespace util = neosystem::util;
namespace http = neosystem::http;

class http_session_reply {
private:
	const config& conf_;

	http::streambuf_cache& cache_;

	bool is_https_;

	void append_set_cookie_header_expires(std::ostream& stream) {
		auto timep = std::chrono::system_clock::now() + std::chrono::minutes(conf_.get_session_timeout_minutes());
		auto t = std::chrono::system_clock::to_time_t(timep);
		struct tm result;
		gmtime_r(&t, &result);
		stream << "Expires=" << http::to_day_name(result) << ", " << std::put_time(&result, "%d ") << http::to_month(result) << std::put_time(&result, " %Y %H:%M:%S GMT");
		return;
	}

	void append_secure(std::ostream& stream) {
		if (is_https_ == false || conf_.is_enable_cookie_secure() == false) {
			return;
		}
		stream << "; Secure";
		return;
	}

	void append_set_cookie_header(std::ostream& stream, const std::string& session_id, const std::string& csrf_token) {
		if (conf_.get_cookie_domain() == "") {
			stream << "Set-Cookie: " << SESSION_ID_KEY_NAME << "=" << session_id << "; ";
			append_set_cookie_header_expires(stream);
			append_secure(stream);
			stream << "; HttpOnly\r\n";

			stream << "Set-Cookie: " << conf_.get_csrf_cookie_name() << "=" << csrf_token << "; ";
			append_set_cookie_header_expires(stream);
			append_secure(stream);
			stream << "\r\n";
			return;
		}
		const auto& domain = conf_.get_cookie_domain();
		stream << "Set-Cookie: " << SESSION_ID_KEY_NAME << "=" << session_id << "; ";
		append_set_cookie_header_expires(stream);
		append_secure(stream);
		stream << "; HttpOnly; Domain=" << domain << "\r\n";

		stream << "Set-Cookie: " << conf_.get_csrf_cookie_name() << "=" << csrf_token << "; ";
		append_set_cookie_header_expires(stream);
		append_secure(stream);
		stream << "; Domain=" << domain << "\r\n";
		return;
	}

public:
	http_session_reply(const config& conf, http::streambuf_cache& cache) : conf_(conf), cache_(cache) {
	}

	http::streambuf_cache::buf_type response_preflight(const proxy_config::ptr_type& proxy_conf, const http::http_request_header& request_header) {
		auto cors_conf = proxy_conf->get_cors_config();

		std::stringstream response_header_stream;
		std::string origin(request_header.find_header("Origin"));
		bool is_allow_origin = false;
		if (origin != "") {
			is_allow_origin = cors_conf->is_allow_origin(origin);
			if (is_allow_origin) {
				response_header_stream << "HTTP/1.1 200 OK\r\n";
			} else {
				response_header_stream << "HTTP/1.1 403 Forbidden\r\n";
			}
		} else {
			response_header_stream << "HTTP/1.1 200 OK\r\n";
		}

		response_header_stream
			<< "Content-Length: 0\r\n"
			<< "Connection: Close\r\n"
			<< "Access-Control-Max-Age: " << cors_conf->get_max_age() << "\r\n"
			;
		if (cors_conf->has_allow_methods()) {
			response_header_stream << "Access-Control-Allow-Methods: " << cors_conf->get_allow_methods() << "\r\n";
		}
		if (cors_conf->has_allow_headers()) {
			response_header_stream << "Access-Control-Allow-Headers: " << cors_conf->get_allow_headers() << "\r\n";
		}
		if (cors_conf->is_allow_credentials()) {
			response_header_stream << "Access-Control-Allow-Credentials: true\r\n";
		}

		if (origin != "" && is_allow_origin) {
			response_header_stream << "Access-Control-Allow-Origin: " << origin << "\r\n";
		}

		response_header_stream << "\r\n";
		return cache_.get(response_header_stream.str().c_str());
	}

	http::streambuf_cache::buf_type start_oauth2(const oauth2_server_config& conf, const std::string& session_id,
												 const std::string& csrf_token, const std::string& state) {
		std::string callback;
		util::urlencode(conf.get_callback_url(), callback);

		std::stringstream response_header_stream;
		response_header_stream
			<< "HTTP/1.1 302 Found\r\n"
			<< "Connection: Close\r\n"
			;
		append_set_cookie_header(response_header_stream, session_id, csrf_token);
		response_header_stream
			<< "Location: " << conf.get_user_authorization_url()
			<< "?client_id=" << conf.get_client_id()
			<< "&scope=" << conf.get_scope()
			<< "&redirect_uri=" << callback
			<< "&state=" << state
			<< "\r\n"
			<< "\r\n"
			;
		return cache_.get(response_header_stream.str().c_str());
	}

	http::streambuf_cache::buf_type redirect_to_login_success(const std::string& session_id, const std::string& csrf_token) {
		std::stringstream response_header_stream;
		response_header_stream
			<< "HTTP/1.1 302 Found\r\n"
			<< "Connection: Close\r\n"
			;
		append_set_cookie_header(response_header_stream, session_id, csrf_token);
		response_header_stream
			<< "Location: " << conf_.get_login_success_redirect() << "\r\n"
			<< "\r\n"
			;
		return cache_.get(response_header_stream.str().c_str());
	}

	http::streambuf_cache::buf_type reply_login(void) {
		std::stringstream response_header_stream;
		response_header_stream
			<< "HTTP/1.1 302 Found\r\n"
			<< "Connection: Close\r\n"
			<< "Location: " << conf_.get_no_login_redirect() << "\r\n"
			<< "Content-Length: 0\r\n"
			<< "\r\n"
			;
		return cache_.get(response_header_stream.str().c_str());
	}

	http::streambuf_cache::buf_type oauth1_redirect(const oauth1_server_config::ptr_type& oauth1_conf, const std::string& oauth_token,
													const std::string& session_id, const std::string& csrf_token) {
		std::stringstream response_header_stream;
		response_header_stream
			<< "HTTP/1.1 302 Found\r\n"
			<< "Connection: Close\r\n"
			;
		append_set_cookie_header(response_header_stream, session_id, csrf_token);
		response_header_stream
			<< "Location: " << oauth1_conf->get_authenticate_url() << "?oauth_token=" << oauth_token << "\r\n"
			<< "\r\n"
			;
		return cache_.get(response_header_stream.str().c_str());
	}

	void set_https(bool is_https) {
		is_https_ = is_https;
		return;
	}
};

}
}

#endif
