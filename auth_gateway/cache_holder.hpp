#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_CACHE_HOLDER_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_CACHE_HOLDER_HPP_

#include "http_common.hpp"
#include "object_cache.hpp"
#include "name_cache.hpp"


namespace poppo {
namespace auth_gateway {

namespace http = neosystem::http;

template<typename SocketType>
class cache_holder {
public:
	using socket_type = SocketType;

private:
	object_cache<socket_type> object_cache_;
	http::streambuf_cache cache_;
	name_cache name_cache_;

public:
	cache_holder(std::size_t cache_size, std::size_t streambuf_cache_size) :object_cache_(cache_size), cache_(streambuf_cache_size) {
	}

	object_cache<socket_type>& get_object_cache(void) { return object_cache_; }
	http::streambuf_cache& get_cache(void) { return cache_; }
	name_cache& get_name_cache(void) { return name_cache_; }
};

}
}

#endif
