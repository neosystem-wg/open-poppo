#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_POPPO_ID_GETTER_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_POPPO_ID_GETTER_

#include <memory>

#include <boost/noncopyable.hpp>

#include "log.hpp"
#include "http_common.hpp"
#include "http_client.hpp"
#include "json_reader.hpp"
#include "json_writer.hpp"
#include "auth_history.hpp"


namespace poppo {
namespace auth_gateway {

using namespace neosystem::wg;
namespace http = neosystem::http;

class poppo_id_getter : public std::enable_shared_from_this<poppo_id_getter>, private boost::noncopyable {
public:
	using self_type = poppo_id_getter;
	using ptr_type = std::shared_ptr<self_type>;
	using callback_func_type = std::function<void (std::unique_ptr<boost::asio::streambuf>, const std::string&)>;

private:
	log::logger& logger_;
	const config& conf_;

	boost::asio::io_context& io_context_;

	http::streambuf_cache& cache_;

	auth_history::ptr_type auth_history_;

	void register_auth_history(const std::string& poppo_id, bool success) {
		if (auth_history_ == nullptr) {
			return;
		}
		auth_history_->set_success(success);

		auto self = std::enable_shared_from_this<self_type>::shared_from_this();
		auto client = http::http_client::create(logger_, io_context_, cache_, [this, self](
				const http::http_client_status& client_status, const http::http_response_header& header,
				const char *, size_t) {
			if (client_status) {
				log::error(logger_)() << S_ << client_status;
				return;
			}
			log::info(logger_)() << S_ << "status code: " << header.get_status_code_str();
			return;
		});

		const auto& url = conf_.get_poppo_url_info();

		auto body_buf = cache_.get();
		std::ostream body(&(*body_buf));
		auth_history_->write_json(body);
		auth_history_.reset();

		auto buf = cache_.get();
		std::ostream stream(&(*buf));
		stream << "POST " << url.get_path() << "/" << poppo_id << "/history" << " HTTP/1.1\r\n";
		stream << "Host: " << url.get_host() << "\r\n";
		stream << "Content-Length: " << body_buf->size() << "\r\n";
		stream << "Content-Type: application/json" << "\r\n";
		stream << "\r\n";

		client->start(url.get_host().c_str(), url.get_port().c_str(), buf, body_buf);
		log::debug(logger_)() << "start register auth history";
		return;
	}

public:
	poppo_id_getter(log::logger& logger, const config& conf,
					boost::asio::io_context& io_context, http::streambuf_cache& cache) :
		logger_(logger), conf_(conf), io_context_(io_context), cache_(cache)  {
	}

	void run(callback_func_type func, auth_provider auth_p, const std::string& user_id) {
		if (user_id == "") {
			auto buf = cache_.get_503();
			func(std::move(buf), "");
			return;
		}

		auto self = std::enable_shared_from_this<self_type>::shared_from_this();
		auto client = http::http_client::create(logger_, io_context_, cache_, [this, self, func](
				const http::http_client_status& client_status, const http::http_response_header& header,
				const char *p, size_t size) {
			log::info(logger_)() << S_ << "status code: " << header.get_status_code_str();

			// HTTPステータスチェック
			if (client_status || header.get_status_code_str() != "200") {
				auto buf = cache_.get_503();
				func(std::move(buf), "");
				log::error(logger_)() << S_ << client_status;
				return;
			}

			std::stringstream stream(std::string(p, size));
			try {
				boost::property_tree::ptree pt;
				json::json_read(stream, pt);

				std::string poppo_id = pt.get("poppoId", "");

				log::info(logger_)() << "poppo_id: " << poppo_id;

				func(nullptr, poppo_id);
				register_auth_history(poppo_id, true);
			} catch (const json::parser_error&) {
				// エラー処理
				log::info(logger_)() << S_ << "Invalid json";
				auto buf = cache_.get_503();
				func(std::move(buf), "");
				return;
			}
			return;
		});

		const auto& url = conf_.get_poppo_url_info();

		auto buf = cache_.get();
		auto body_buf = cache_.get();
		std::ostream stream(&(*buf));
		std::ostream body(&(*body_buf));

		// リクエストJSON
		auto req = json::object::create();

		auto federated_id = json::object::create();
		federated_id->add("type", auth_provider_to_string(auth_p));
		federated_id->add("value", user_id);

		auto federated_id_list = json::array::create();
		federated_id_list->add(federated_id);

		req->add("federatedId", federated_id_list);
		body << (*req);

		stream << "POST " << url.get_path() << " HTTP/1.1\r\n";
		stream << "Host: " << url.get_host() << "\r\n";
		stream << "Content-Length: " << body_buf->size() << "\r\n";
		stream << "Content-Type: application/json" << "\r\n";
		stream << "\r\n";

		client->start(url.get_host().c_str(), url.get_port().c_str(), buf, body_buf);
		return;
	}

	void set_auth_history(const auth_history::ptr_type& auth_h) {
		auth_history_ = auth_h;
		return;
	}
};

}
}

#endif
