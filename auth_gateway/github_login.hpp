#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_GITHUB_LOGIN_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_GITHUB_LOGIN_

#include "log.hpp"
#include "http_common.hpp"
#include "http_client.hpp"
#include "json_reader.hpp"
#include "json_writer.hpp"


namespace poppo {
namespace auth_gateway {

using namespace neosystem::wg;
namespace util = neosystem::util;

class github_login {
public:
	using self_type = github_login;
	using ptr_type = std::shared_ptr<self_type>;
	using callback_func_type = std::function<void (int, const std::string&)>;

private:
	log::logger& logger_;
	const oauth2_server_config::ptr_type conf_;

	boost::asio::io_context& io_context_;

	http::streambuf_cache& cache_;

	void get_user_info(const callback_func_type& func, const std::string& access_token) {
		auto client = http::https_client::create(logger_, io_context_, cache_, [this, func](
				const http::http_client_status& client_status, const http::http_response_header& header,
				const char *p, size_t size) {
			if (client_status || header.get_status_code_str() != "200") {
				log::info(logger_)() << S_ << client_status << ", HTTP_STATUS: " << header.get_status_code_str();
				func(503, "");
				return;
			}
			log::info(logger_)() << S_ << "HTTP_STATUS: " << header.get_status_code_str();

			std::stringstream stream(std::string(p, size));
			try {
				boost::property_tree::ptree pt;
				json::json_read(stream, pt);

				std::string id = pt.get("id", "");

				log::info(logger_)() << S_ << "user_id [" << id << "]";

				func(200, id);
			} catch (const json::parser_error&) {
				// エラー処理
				log::info(logger_)() << S_ << "Invalid json";
				func(503, "");
				return;
			}
			return;
		});

		const auto& url = conf_->get_user_info_url_info();

		auto buf = cache_.get();
		std::ostream stream(&(*buf));

		stream << "GET " << url.get_path() << " HTTP/1.1\r\n";
		stream << "Host: " << url.get_host() << "\r\n";
		stream << "Authorization: token " << access_token << "\r\n";
		stream << "Accept: application/json\r\n";
		stream << "User-Agent: auth_gateway\r\n";
		stream << "\r\n";

		client->start(url.get_host().c_str(), url.get_port().c_str(), buf);
		return;
	}

public:
	github_login(log::logger& logger, const oauth2_server_config::ptr_type& conf,
				 boost::asio::io_context& io_context, http::streambuf_cache& cache) :
		logger_(logger), conf_(conf), io_context_(io_context), cache_(cache) {
	}

	void login(const callback_func_type& func, const std::string& code) {
		auto client = http::https_client::create(logger_, io_context_, cache_, [this, func](
				const http::http_client_status& client_status, const http::http_response_header& header,
				const char *p, size_t size) {
			if (client_status || header.get_status_code_str() != "200") {
				log::info(logger_)() << S_ << client_status << ", HTTP_STATUS: " << header.get_status_code_str();
				func(503, "");
				return;
			}
			log::info(logger_)() << S_ << "HTTP_STATUS: " << header.get_status_code_str();

			std::stringstream stream(std::string(p, size));
			try {
				boost::property_tree::ptree pt;
				json::json_read(stream, pt);

				std::string access_token = pt.get("access_token", "");
				get_user_info(func, access_token);
			} catch (const json::parser_error&) {
				// エラー処理
				log::info(logger_)() << S_ << "Invalid json";
				func(503, "");
				return;
			}
			return;
		});

		const auto& url = conf_->get_access_token_url_info();

		auto buf = cache_.get();
		std::ostream stream(&(*buf));

		std::string callback;
		util::urlencode(conf_->get_callback_url(), callback);

		stream << "GET " << url.get_path() << "?client_id=" << conf_->get_client_id() << "&client_secret=" << conf_->get_client_secret()
			<< "&code=" << code << "&redirect_uri=" << callback << " HTTP/1.1\r\n";
		stream << "Host: " << url.get_host() << "\r\n";
		stream << "Accept: application/json\r\n";
		stream << "\r\n";

		client->start(url.get_host().c_str(), url.get_port().c_str(), buf);
		return;
	}
};

}
}

#endif
