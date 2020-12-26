#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_SESSION_MANAGER_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_SESSION_MANAGER_HPP_

#include <unordered_map>
#include <queue>

#include <boost/asio.hpp>

#include "session.hpp"
#include "redis_command_executor.hpp"


namespace poppo {
namespace auth_gateway {

class session_manager_impl;

using session_timeout_pair_type = std::pair<std::string, std::chrono::system_clock::time_point>;
using session_timeout_type = std::shared_ptr<session_timeout_pair_type>;

struct session_compare {
	bool operator()(const session_timeout_type& a, const session_timeout_type& b) {
		return a->second > b->second;
	}
};

class session_manager {
public:
	using callback_func_type = std::function<void (const boost::system::error_code&, const redis_command_status&, const session_ptr_type&)>;

private:
	static session_compare c_;

	neosystem::wg::log::logger& logger_;

	std::string addr_;
	std::string port_;
	std::unique_ptr<session_manager_impl> impl_;

	std::shared_mutex mutex_;
	std::unordered_map<std::string, session_ptr_type> value_;

	std::shared_mutex timeout_q_mutex_;
	std::priority_queue<session_timeout_type, std::vector<session_timeout_type>, decltype(c_)> timeout_q_;

	const int session_timeout_minutes_;

	void append_timeout_q(const session_timeout_type& session);
	session_timeout_type get_timeout_q_top(void);
	bool put_impl(const std::string&, const session_ptr_type&);

public:
	session_manager(void);
	session_manager(const std::string&, const std::string&);
	~session_manager(void);

	void run(void);

	session_ptr_type get(const std::string&);
	void get(const std::string&, boost::asio::io_context&, const callback_func_type&);

	void put(const std::string&, const session_ptr_type&);
	void remove(const std::string&);
	void remove_timeout_session(void);
};

}
}

#endif
