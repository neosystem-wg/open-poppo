#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_OBJECT_CACHE_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_OBJECT_CACHE_HPP_

#include <vector>

#include <boost/intrusive_ptr.hpp>


namespace poppo {
namespace auth_gateway {

template<typename SessionType>
class http_session;

template<typename T>
class reverse_proxy_client;

template<typename SocketType>
class object_cache {
public:
	using session_type = http_session<SocketType>;

	using client_type = reverse_proxy_client<typename session_type::ptr_type>;

private:
	bool shutdown_flag_;
	std::size_t max_size_;

	std::vector<client_type *> client_cache_;

	std::vector<session_type *> session_cache_;

	template<typename T>
	void destruct(std::vector<T *>& v) {
		for (auto it = v.begin(); it != v.end(); ++it) {
			delete ((T *) (*it));
		}
		v.clear();
		return;
	}

public:
	object_cache(std::size_t max_size) : shutdown_flag_(false), max_size_(max_size) {
	}

	~object_cache(void) {
		destruct(client_cache_);
		destruct(session_cache_);
	}

	void shutdown(void) {
		shutdown_flag_ = true;
		destruct(client_cache_);
		destruct(session_cache_);
		return;
	}

	client_type *get_client(void) {
		if (client_cache_.empty()) return nullptr;
		client_type *tmp = *(client_cache_.rbegin());
		client_cache_.pop_back();
		return tmp;
	}

	session_type *get_session(void) {
		if (session_cache_.empty()) return nullptr;
		session_type *tmp = *(session_cache_.rbegin());
		session_cache_.pop_back();
		return tmp;
	}

	bool release(client_type *ptr) {
		if (shutdown_flag_ || client_cache_.size() >= max_size_) return false;
		client_cache_.push_back(ptr);
		return true;
	}

	bool release(session_type *ptr) {
		if (shutdown_flag_ || session_cache_.size() >= max_size_) return false;
		session_cache_.push_back(ptr);
		return true;
	}

};

}
}

#endif
