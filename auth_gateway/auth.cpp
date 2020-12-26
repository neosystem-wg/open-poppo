#include <string.h>

#include "auth.hpp"


namespace poppo {
namespace auth_gateway {

auth_provider string_to_auth_provider(const char *s) {
	if (strcasecmp(s, "twitter") == 0) {
		return auth_provider::TWITTER;
	} else if (strcasecmp(s, "github") == 0) {
		return auth_provider::GITHUB;
	} else if (strcasecmp(s, "slack") == 0) {
		return auth_provider::SLACK;
	}
	return auth_provider::UNKNOWN;
}

const char *auth_provider_to_string(auth_provider a) {
	switch (a) {
	case auth_provider::TWITTER:
		return "tw";
	case auth_provider::GITHUB:
		return "gi";
	case auth_provider::SLACK:
		return "sl";
	case auth_provider::UNKNOWN:
		break;
	}
	return "xx";
}

}
}
