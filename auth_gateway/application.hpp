#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_APPLICATION_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_APPLICATION_HPP_

#include <memory>
#include <thread>

#include "log.hpp"
#include "config.hpp"
#include "http_common.hpp"


namespace poppo {
namespace auth_gateway {

constexpr const char *SESSION_ID_KEY_NAME = "korat_session_id";
constexpr const char *POST_CSRF_TOKEN_NAME = "csrf_token";

class session_manager;
class application_impl;
class async_access_logger;
class log_object;

class application {
private:
	static volatile bool stop_flag_;
	static neosystem::wg::log::logger logger_;
	static config conf_;
	static std::unique_ptr<session_manager> session_;
	std::unique_ptr<std::thread> session_thread_;
	static std::unique_ptr<async_access_logger> access_logger_;
	std::unique_ptr<std::thread> access_log_thread_;

	application_impl *impl_;

public:
	application(void);
	~application(void);

	int run(void);
	void stop(void);

	static void show_version(void);
	static bool static_member_init(const std::string&);
	static neosystem::wg::log::logger& get_logger(void) { return logger_; }
	static const config& get_config(void) { return conf_; }
	static bool is_application_stop(void) { return stop_flag_; }
	static session_manager& get_session(void) { return *session_; }
	static void access_log(const std::shared_ptr<log_object>&);
};

}
}

#endif
