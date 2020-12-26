#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_REDIS_COMMAND_EXECUTOR_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_REDIS_COMMAND_EXECUTOR_HPP_

#include <vector>

#include <bredis/Connection.hpp>
#include <bredis/Extract.hpp>

#include "session_manager.hpp"
#include "common.hpp"


namespace poppo {
namespace auth_gateway {

enum class redis_command_status {
	success,
	system_error,
	connection_error,
	connection_timeout,
	command_timeout,
};

template<typename Pool>
class redis_command_executor : public std::enable_shared_from_this<redis_command_executor<Pool>>, private boost::noncopyable {
public:
	using get_command_callback_type = std::function<void (const boost::system::error_code&, redis_command_status, const std::string&)>;

private:
	using pool_type = Pool;
	using self_type = redis_command_executor<pool_type>;

	using bredis_connection_type = typename pool_type::bredis_connection_type;
	using iterator_type = typename bredis::to_iterator<boost::asio::streambuf>::iterator_t;
	using policy_type = bredis::parsing_policy::keep_result;
	using result_type = bredis::parse_result_mapper_t<iterator_type, policy_type>;

	pool_type& impl_;

	boost::asio::ip::tcp::resolver resolver_;
	std::unique_ptr<bredis_connection_type> conn_;

	boost::asio::streambuf buf_;

	boost::asio::streambuf rx_buff_;

	std::function<void (redis_command_status)> after_connect_;

	void handle_connect(std::unique_ptr<boost::asio::ip::tcp::socket> socket,
			const boost::system::error_code& error, boost::asio::ip::tcp::resolver::iterator endpoint_iterator) {
		if (error == boost::asio::error::operation_aborted) {
			after_connect_(redis_command_status::connection_error);
			return;
		}

		if (!error) {
			if (after_connect_ != nullptr) {
				conn_ = std::make_unique<bredis_connection_type>(std::move(*socket));
				after_connect_(redis_command_status::success);
			}
			return;
		}

		if (endpoint_iterator != boost::asio::ip::tcp::resolver::iterator()) {
			boost::system::error_code ec;
			socket->close(ec);

			boost::asio::ip::tcp::endpoint endpoint = *endpoint_iterator;
			++endpoint_iterator;
			auto self = std::enable_shared_from_this<self_type>::shared_from_this();
			socket->async_connect(
				endpoint,
				[this, self, socket = std::move(socket), endpoint_iterator](const boost::system::error_code& ec1) mutable {
					handle_connect(std::move(socket), ec1, endpoint_iterator);
					return;
				}
				);
			return;
		}

		after_connect_(redis_command_status::connection_error);
		return;
	}

	void connect(const std::string& host, const std::string& port) {
		boost::asio::ip::tcp::resolver::query query(host.c_str(), port.c_str());
		auto self = std::enable_shared_from_this<self_type>::shared_from_this();
		resolver_.async_resolve(query,
				[this, self](const boost::system::error_code& error, boost::asio::ip::tcp::resolver::iterator endpoint_iterator) {
			if (error == boost::asio::error::operation_aborted) {
				after_connect_(redis_command_status::connection_error);
				return;
			}
			if (error) {
				std::cerr << S_ << " Error: resolve failed. (message: " << error.message() << ")" << std::endl;
				after_connect_(redis_command_status::connection_error);
				return;
			}

			auto socket = std::make_unique<boost::asio::ip::tcp::socket>(impl_.get_io_context());
		
			boost::asio::ip::tcp::endpoint endpoint = *endpoint_iterator;
			++endpoint_iterator;
			socket->async_connect(
				endpoint,
				[this, self, socket = std::move(socket), endpoint_iterator](const boost::system::error_code& ec1) mutable {
					handle_connect(std::move(socket), ec1, endpoint_iterator);
					return;
				}
				);
			return;
		});
		return;
	}

	void read_get_result(get_command_callback_type f) {
		auto self = std::enable_shared_from_this<self_type>::shared_from_this();
		conn_->async_read(rx_buff_, [this, self, f](const auto &ec, auto&& r) {
			if (ec) {
				std::cerr << S_ << ec.message() << std::endl;
				f(ec, redis_command_status::system_error, "");
				return;
			}
			auto extract = boost::apply_visitor(bredis::extractor<iterator_type>(), r.result);
			if (extract.which() == 1) {
				auto &reply_str = boost::get<bredis::extracts::string_t>(extract);
				rx_buff_.consume(r.consumed);
				f(ec, redis_command_status::success, reply_str.str);
			} else {
				f(ec, redis_command_status::success, "");
			}
			return;
		});
		return;
	}

	void read_result(void) {
		auto self = std::enable_shared_from_this<self_type>::shared_from_this();
		conn_->async_read(rx_buff_, [this, self](const auto &ec, auto&& r) {
			if (ec) {
				std::cerr << S_ << ec.message() << std::endl;
				conn_.reset();
				return;
			}
			//auto extract = boost::apply_visitor(bredis::extractor<iterator_type>(), r.result);
			//auto &reply_str = boost::get<bredis::extracts::string_t>(extract);
            rx_buff_.consume(r.consumed);
			return;
		});
		return;
	}

public:
	redis_command_executor(pool_type& impl)
		: impl_(impl), resolver_(impl.get_io_context()) {
	}

	redis_command_executor(pool_type& impl,
			std::unique_ptr<bredis_connection_type> conn) : impl_(impl), resolver_(impl.get_io_context()), conn_(std::move(conn)) {
	}

	~redis_command_executor(void) {
		if (conn_ != nullptr) impl_.release(conn_);
	}

	void get(const std::string& key, const get_command_callback_type& f) {
		if (conn_ == nullptr) {
			auto param = std::make_shared<std::string>(key);
			after_connect_ = std::move([this, param1 = std::move(param), f](redis_command_status status) {
				if (status != redis_command_status::success) {
					std::cout << S_ << "redis connection error" << std::endl;
					boost::system::error_code ec;
					f(ec, status, "");
					return;
				}
				get(*param1, f);
				return;
			});
			connect(impl_.get_host(), impl_.get_port());
			return;
		}

    	bredis::single_command_t command{"GET", key};

    	bredis::command_container_t cmd_container;
		cmd_container.push_back(command);

		bredis::command_wrapper_t command_wrapper{std::move(cmd_container)};

		auto self = std::enable_shared_from_this<self_type>::shared_from_this();
		conn_->async_write(buf_, command_wrapper, [this, self, f](const boost::system::error_code& ec, auto bytes_transferred) {
			if (ec) {
				std::cerr << S_ << ec.message() << std::endl;
				conn_.reset();
				return;
			}
			buf_.consume(bytes_transferred);
			read_get_result(f);
			return;
		});
		return;
	}

	void remove(const std::string& key) {
		if (conn_ == nullptr) {
			auto param = std::make_shared<std::string>(key);
			after_connect_ = std::move([this, param1 = std::move(param)](redis_command_status status) {
				if (status != redis_command_status::success) {
					std::cout << S_ << "redis connection error" << std::endl;
					return;
				}
				remove(*param1);
				return;
			});
			connect(impl_.get_host(), impl_.get_port());
			return;
		}

    	bredis::single_command_t command{"DEL", key};

    	bredis::command_container_t cmd_container;
		cmd_container.push_back(command);

		bredis::command_wrapper_t command_wrapper{std::move(cmd_container)};

		auto self = std::enable_shared_from_this<self_type>::shared_from_this();
		conn_->async_write(buf_, command_wrapper, [this, self](const boost::system::error_code& ec, auto bytes_transferred) {
			if (ec) {
				std::cerr << S_ << ec.message() << std::endl;
				conn_.reset();
				return;
			}
			buf_.consume(bytes_transferred);
			read_result();
			return;
		});
		return;
	}

	void set_and_expire(const std::string& key, const std::string& value, const std::string& expire_time) {
		if (conn_ == nullptr) {
			auto param = std::make_shared<std::string>(key);
			auto value_param = std::make_shared<std::string>(value);
			after_connect_ = std::move([this, param1 = std::move(param), value_param = std::move(value_param),
									   expire_time = std::move(expire_time)](redis_command_status status) {
				if (status != redis_command_status::success) {
					std::cout << S_ << "redis connection error" << std::endl;
					return;
				}
				set_and_expire(*param1, *value_param, expire_time);
				return;
			});
			connect(impl_.get_host(), impl_.get_port());
			return;
		}

    	bredis::single_command_t command{"SET", key, value};

    	bredis::command_container_t cmd_container;
		cmd_container.push_back(command);

    	bredis::single_command_t ttl_command{"EXPIRE", key, expire_time};
		cmd_container.push_back(ttl_command);

		bredis::command_wrapper_t command_wrapper{std::move(cmd_container)};

		auto self = std::enable_shared_from_this<self_type>::shared_from_this();
		conn_->async_write(buf_, command_wrapper, [this, self](const boost::system::error_code& ec, auto bytes_transferred) {
			if (ec) {
				std::cerr << S_ << ec.message() << std::endl;
				conn_.reset();
				return;
			}
			buf_.consume(bytes_transferred);
			read_result();
			return;
		});
		return;
	}
};

}
}

#endif
