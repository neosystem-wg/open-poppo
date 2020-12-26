#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_NAME_CACHE_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_NAME_CACHE_HPP_

#include <unordered_map>

#include <boost/asio.hpp>


namespace poppo {
namespace auth_gateway {

class resolve_results {
public:
	using ptr_type = std::unique_ptr<resolve_results>;

private:
	boost::asio::ip::tcp::resolver::results_type results_;

	boost::asio::ip::tcp::resolver::results_type::iterator it_;

public:
	resolve_results(const boost::asio::ip::tcp::resolver::results_type& r) : results_(r), it_(results_.begin()) {
	}

	boost::asio::ip::tcp::endpoint get(void) {
		++it_;
		if (it_ == results_.end()) it_ = results_.begin();
		return *it_;
	}
};

class name_cache {
private:
	std::unordered_map<std::string, resolve_results::ptr_type> cache_;

public:
	void add(const std::string& name, const boost::asio::ip::tcp::resolver::results_type& r) {
		cache_[name] = std::make_unique<resolve_results>(r);
		return;
	}

	bool get(const std::string& name, boost::asio::ip::tcp::endpoint& e) {
		auto it = cache_.find(name);
		if (it == cache_.end()) return false;
		e = it->second->get();
		return true;
	}
};

}
}

#endif
