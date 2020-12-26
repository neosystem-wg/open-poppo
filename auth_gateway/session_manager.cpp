#include <vector>

#include <bredis/Connection.hpp>

#include "application.hpp"
#include "session_manager.hpp"
#include "common.hpp"
#include "redis_command_executor.hpp"
#include "log.hpp"


namespace poppo {
namespace auth_gateway {

using namespace neosystem::wg;

session_compare session_manager::c_;


class session_manager_impl {
public:
    using bredis_next_layer_type = boost::asio::ip::tcp::socket;
	using bredis_connection_type = bredis::Connection<bredis_next_layer_type>;

private:
	using self_type = session_manager_impl;
	using executor_type = redis_command_executor<self_type>;

	std::string host_;
	std::string port_;
	boost::asio::io_context io_context_;
	boost::asio::steady_timer timer_;

	std::vector<std::unique_ptr<bredis_connection_type>> pool_;

	void exit_check(void) {
		timer_.expires_from_now(std::chrono::milliseconds(1000));
		timer_.async_wait([this](const boost::system::error_code& error) {
			if (error == boost::asio::error::operation_aborted) {
				return;
			}
			exit_check();
			return;
		});
		return;
	}

public:
	session_manager_impl(const std::string& host, const std::string& port) : host_(host), port_(port), timer_(io_context_){
	}

	void run(void) {
		exit_check();

		boost::asio::signal_set signals(io_context_, SIGINT, SIGTERM);
		signals.async_wait([this](const boost::system::error_code&, int) {
			io_context_.stop();
		});

		io_context_.run();
		return;
	}

	void release(std::unique_ptr<session_manager_impl::bredis_connection_type>& conn) {
		pool_.push_back(std::move(conn));
		return;
	}

	void get(const std::string& session_id, boost::asio::io_context& context,
			 const session_manager::callback_func_type& f) {
		auto callback = [this, f, &context](const boost::system::error_code& ec, redis_command_status status, const std::string& value) mutable {
			//std::cout << S_ << value << std::endl;
			if (ec || status != redis_command_status::success || value == "") {
				boost::asio::post(context, [f, ec, status] { f(ec, status, nullptr); });
				return;
			}
			auto p = session::create_from_string(value);
			boost::asio::post(context, [f, ec, status, p] { f(ec, status, p); });
			return;
		};
		if (pool_.empty()) {
			// 接続
			std::make_shared<executor_type>(*this)->get(session_id, callback);
			return;
		}

		auto conn = std::move(*pool_.rbegin());
		pool_.pop_back();
		std::make_shared<executor_type>(*this, std::move(conn))->get(session_id, callback);
		return;
	}

	void remove(const std::string& session_id) {
		if (pool_.empty()) {
			// 接続
			std::make_shared<executor_type>(*this)->remove(session_id);
			return;
		}

		auto conn = std::move(*pool_.rbegin());
		pool_.pop_back();
		std::make_shared<executor_type>(*this, std::move(conn))->remove(session_id);
		return;
	}

	void put(const std::string& session_id, const session_ptr_type& ptr) {
		std::string value;
		ptr->to_string(value);

		if (pool_.empty()) {
			// 接続
			std::make_shared<executor_type>(*this)->set_and_expire(session_id, value, "600");
			return;
		}

		auto conn = std::move(*pool_.rbegin());
		pool_.pop_back();
		std::make_shared<executor_type>(*this, std::move(conn))->set_and_expire(session_id, value, "600");
		return;
	}

	boost::asio::io_context& get_io_context(void) { return io_context_; }
	const std::string& get_host(void) const { return host_; }
	const std::string& get_port(void) const { return port_; }
};


session_manager::session_manager(void) : logger_(application::get_logger()), impl_(nullptr),
	session_timeout_minutes_(application::get_config().get_session_timeout_minutes()) {
}

session_manager::session_manager(const std::string& addr, const std::string& port) : logger_(application::get_logger()),
	addr_(addr), port_(port),
	session_timeout_minutes_(application::get_config().get_session_timeout_minutes()) {
	impl_ = std::make_unique<session_manager_impl>(addr, port);
}

session_manager::~session_manager(void) {
}

void session_manager::run(void) {
	if (impl_ == nullptr) {
		return;
	}
	impl_->run();
	return;
}

void session_manager::get(const std::string& session_id, boost::asio::io_context& context,
		const callback_func_type& f) {
	if (impl_ == nullptr) {
		return;
	}
	write_lock lock(mutex_);
	impl_->get(session_id, context, f);
	return;
}

session_ptr_type session_manager::get(const std::string& key) {
	read_lock lock(mutex_);
	auto it = value_.find(key);
	if (it == value_.end()) {
		return nullptr;
	}
	return it->second;
}

bool session_manager::put_impl(const std::string& key, const session_ptr_type& session) {
	write_lock lock(mutex_);
	if (impl_ != nullptr) impl_->put(key, session);

	bool is_already_exist = false;
	auto it = value_.find(key);
	if (it != value_.end()) is_already_exist = true;
	value_[key] = session;
	return is_already_exist;
}

void session_manager::put(const std::string& key, const session_ptr_type& session) {
	bool is_already_exist = put_impl(key, session);
	if (!is_already_exist) {
		append_timeout_q(std::make_shared<session_timeout_pair_type>(key, session->get_last_access_time()));
	}
	return;
}

session_timeout_type session_manager::get_timeout_q_top(void) {
	write_lock lock(timeout_q_mutex_);
	if (timeout_q_.empty()) return nullptr;
	auto s = timeout_q_.top();
	auto period = std::chrono::system_clock::now() - std::chrono::minutes(session_timeout_minutes_);
	if (period < s->second) return nullptr;
	timeout_q_.pop();
	return s;
}

void session_manager::append_timeout_q(const session_timeout_type& s) {
	write_lock lock(timeout_q_mutex_);
	timeout_q_.push(s);
	return;
}

void session_manager::remove(const std::string& key) {
	write_lock lock(mutex_);
	if (impl_ != nullptr) impl_->remove(key);
	auto it = value_.find(key);
	if (it == value_.end()) return;
	value_.erase(it);
	return;
}

void session_manager::remove_timeout_session(void) {
	//log::debug(logger_)() << "start remove";
	auto period = std::chrono::system_clock::now() - std::chrono::minutes(session_timeout_minutes_);
	while (true) {
		auto s = get_timeout_q_top();
		if (s == nullptr) break;

		auto session = get(s->first);
		if (session == nullptr) continue;

		if (s->second < session->get_last_access_time() && period < session->get_last_access_time()) {
			log::debug(logger_)() << "update last access_time: " << s->first;
			s->second = session->get_last_access_time();
			append_timeout_q(s);
		} else {
			log::debug(logger_)() << "remove session: " << s->first;
			remove(s->first);
		}
	}
	//log::debug(logger_)() << "end remove";
	return;
}

}
}
