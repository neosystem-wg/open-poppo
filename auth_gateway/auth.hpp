#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_AHTH_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_AHTH_HPP_

namespace poppo {
namespace auth_gateway {

enum class auth_provider {
	UNKNOWN,
	TWITTER,
	GITHUB,
	SLACK
};

auth_provider string_to_auth_provider(const char *);
const char *auth_provider_to_string(auth_provider);

}
}

#endif
