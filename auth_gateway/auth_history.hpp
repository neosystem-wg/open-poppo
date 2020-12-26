#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_AUTH_HISTORY_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_AUTH_HISTORY_HPP_

#include <memory>

#include "auth.hpp"
#include "json_writer.hpp"


namespace poppo {
namespace auth_gateway {

class auth_history {
public:
	using self_type = auth_history;
	using ptr_type = std::shared_ptr<auth_history>;

private:
	auth_provider auth_provider_;
	const std::string ip_addr_;
	const std::string user_agent_;
	bool success_;

public:
	auth_history(auth_provider auth_provider, const std::string& ip_addr, const std::string& user_agent)
		: auth_provider_(auth_provider), ip_addr_(ip_addr), user_agent_(user_agent) {
	}

	void write_json(std::ostream& stream) const {
		auto req = json::object::create();
		req->add("federatedIdType", auth_provider_to_string(auth_provider_));
		req->add("success", success_);
		req->add("ipAddr", ip_addr_);
		req->add("userAgent", user_agent_);
		stream << (*req);
		return;
	}

	auth_provider get_auth_provider(void) const { return auth_provider_; }
	const std::string& get_ip_addr(void) const { return ip_addr_; }
	const std::string& get_user_agent(void) const { return user_agent_; }
	bool is_success(void) const { return success_; }
	void set_success(bool success) { success_ = success; }
};

}
}

#endif
