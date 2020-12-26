#ifndef NEOSYSTEM_POPPO_AUTH_GATEWAY_OAUTH1_HPP_
#define NEOSYSTEM_POPPO_AUTH_GATEWAY_OAUTH1_HPP_

#include <string>

#include "config.hpp"


namespace poppo {
namespace auth_gateway {

void append_authorize_header(const oauth1_server_config&, std::ostream&);
void append_authorize_header2(const oauth1_server_config&, std::ostream&, const std::string&, const std::string&);

}
}

#endif
