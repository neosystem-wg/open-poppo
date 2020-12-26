#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_TWITTER_LOGIN_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_TWITTER_LOGIN_

#include "log.hpp"
#include "http_common.hpp"
#include "http_client.hpp"
#include "oauth1.hpp"


namespace poppo {
namespace auth_gateway {

using namespace neosystem::wg;
namespace http = neosystem::http;

class twitter_login {
public:
	using self_type = twitter_login;
	using ptr_type = std::shared_ptr<self_type>;
	using callback_func_type = std::function<void (int, const std::string&)>;

private:
	log::logger& logger_;
	boost::asio::io_context& io_context_;
	http::streambuf_cache& cache_;

public:
	twitter_login(log::logger& logger, boost::asio::io_context& io_context,
				  http::streambuf_cache& cache) : logger_(logger), io_context_(io_context), cache_(cache) {
	}

	void start_oauth1(const oauth1_server_config& conf, const callback_func_type& func) {
		auto client = http::https_client::create(logger_, io_context_, cache_, [this, func](
					const http::http_client_status& client_status, const http::http_response_header& header,
					const char *p, size_t size) {
			if (client_status || header.get_status_code_str() != "200") {	
				func(503, "");
				log::info(logger_)() << S_ << client_status << ", HTTP_STATUS: " << header.get_status_code_str();
				return;
			}
			log::info(logger_)() << S_ << "HTTP_STATUS: " << header.get_status_code_str();

			// redirect
			std::unordered_map<std::string, std::string> params;
			http::parse_http_post(std::string(p, size), params);

			std::string oauth_token(params["oauth_token"]);
			func(200, oauth_token);
			return;
		});

		const auto& url = conf.get_request_token_url_info();

		auto buf = cache_.get();
		std::ostream stream(&(*buf));

		stream << "POST " << url.get_path() << " HTTP/1.1\r\n";
		stream << "Host: " << url.get_host() << "\r\n";
		stream << "Accept: */*\r\n";
		append_authorize_header(conf, stream);
		stream << "\r\n";

		client->start(url.get_host().c_str(), url.get_port().c_str(), buf);
		return;
	}

	void get_oauth1_access_token(const oauth1_server_config& conf, const std::string& oauth_verifier, const std::string& oauth_token,
								 const callback_func_type& func) {
		auto client = http::https_client::create(logger_, io_context_, cache_, [this, func](
					const http::http_client_status& client_status, const http::http_response_header& header,
					const char *p, size_t size) {
			if (client_status || header.get_status_code_str() != "200") {	
				func(503, "");
				log::info(logger_)() << S_ << client_status << ", HTTP_STATUS: " << header.get_status_code_str();
				return;
			}
			log::info(logger_)() << S_ << "HTTP_STATUS: " << header.get_status_code_str();

			// user id -> poppo_id
			std::unordered_map<std::string, std::string> params;
			http::parse_http_post(std::string(p, size), params);

			auto user_id_it = params.find("user_id");
			if (user_id_it == params.end()) {
				auto buf = cache_.get_503();
				func(200, "");
				return;
			}

			log::info(logger_)() << S_ << "user_id [" << user_id_it->second << "]";

			// redirect
			//get_poppo_id(auth_provider::TWITTER, user_id_it->second);
			func(200, user_id_it->second);
			return;
		});

		const auto& url = conf.get_access_token_url_info();

		auto buf = cache_.get();
		std::ostream stream(&(*buf));

		//log::info(logger_)() << url.get_path() << " [" << oauth_verifier << "], [" << oauth_token << "]";

		stream << "POST " << url.get_path() << " HTTP/1.1\r\n";
		stream << "Host: " << url.get_host() << "\r\n";
		stream << "Accept: */*\r\n";
		append_authorize_header2(conf, stream, oauth_verifier, oauth_token);
		stream << "\r\n";

		client->start(url.get_host().c_str(), url.get_port().c_str(), buf);
		return;
	}

};

}
}

#endif
