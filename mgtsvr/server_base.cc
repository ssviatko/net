#include "server_base.h"

namespace ss {
namespace net {

server_base::server_base(const std::string& a_category)
: ss::net::auth(ss::net::auth::role::SERVER)
, m_category(a_category)
{
	ss::icr& l_icr = ss::icr::get();

	if (!l_icr.key_is_defined(m_category, "port")) {
		ctx.log_p(ss::log::NOTICE, "key <port> must be defined in ini file, exiting!");
		throw std::runtime_error("server_base: key <port> must be defined in ini file, exiting!");
	}
	if (!l_icr.key_is_defined(m_category, "unix_socket")) {
		ctx.log_p(ss::log::NOTICE, "key <unix_socket> must be defined in ini file, exiting!");
		throw std::runtime_error("server_base: key <unix_socket> must be defined in ini file, exiting!");
	}
	if (!l_icr.key_is_defined(m_category, "enable_tcp")) {
		ctx.log_p(ss::log::NOTICE, "key <enable_tcp> must be defined in ini file, exiting!");
		throw std::runtime_error("server_base: key <enable_tcp> must be defined in ini file, exiting!");
	}
	if (!l_icr.key_is_defined(m_category, "enable_unix")) {
		ctx.log_p(ss::log::NOTICE, "key <enable_unix> must be defined in ini file, exiting!");
		throw std::runtime_error("server_base: key <enable_unix> must be defined in ini file, exiting!");
	}

	bool l_enable_tcp = l_icr.to_boolean(l_icr.keyvalue(m_category, "enable_tcp"));
	bool l_enable_unix = l_icr.to_boolean(l_icr.keyvalue(m_category, "enable_unix"));
	// got to have one or the other, can't disable both of them
	if (!l_enable_tcp && !l_enable_unix) {
		ctx.log_p(ss::log::NOTICE, "one or both of the available listening methods must be enabled, exiting!");
		throw std::runtime_error("server_base: one or both of the available listening methods must be enabled, exiting!");
	}

}

server_base::~server_base()
{
	
}

void server_base::shutdown()
{
	ctx.log("Shutting down server_base subsystem..");
}

} // namespace net
} // namespace ss
