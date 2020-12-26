#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_SESSION_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_SESSION_HPP_

#include <string>
#include <memory>
#include <shared_mutex>
#include <chrono>

#include "auth.hpp"
#include "config.hpp"


namespace poppo {
namespace auth_gateway {

class session;
using session_ptr_type = std::shared_ptr<session>;

class session {
public:
	using self_type = session;
	using ptr_type = std::shared_ptr<self_type>;

private:
	mutable std::shared_mutex mutex_;

	std::string request_token_;

	std::string access_token_;

	auth_provider provider_;

	std::string external_id_;

	std::string poppo_id_;

	oauth1_server_config::ptr_type oauth1_config_;

	std::string csrf_token_;

	std::string state_;

	std::chrono::system_clock::time_point last_access_time_;

public:
	session(void);

	static session_ptr_type create(void);
	static session_ptr_type create_from_string(const std::string&);

	void set_request_token(const std::string&);
	std::string get_request_token(void) const;

	void set_access_token(const std::string&);
	std::string get_access_token(void) const;

	void set_provider(auth_provider p) { provider_ = p; }
	auth_provider get_provider(void) const { return provider_; }

	void set_external_id(const std::string&);
	std::string get_external_id(void) const;

	void set_poppo_id(const std::string&);
	std::string get_poppo_id(void) const;

	void set_oauth1_config(const oauth1_server_config::ptr_type&);
	oauth1_server_config::ptr_type get_oauth1_config(void) const;

	void set_csrf_token(const std::string&);
	std::string get_csrf_token(void) const;

	std::chrono::system_clock::time_point get_last_access_time(void) const { return last_access_time_; }
	void update_last_access_time(void);

	void set_state(const std::string&);
	std::string get_state(void) const;

	void to_string(std::string&) const;
};

}
}

#endif
