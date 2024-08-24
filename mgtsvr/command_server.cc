#include "command_server.h"

namespace ss {
namespace net {

command_server::command_server(const std::string& a_category, const std::string& a_auth_db)
: ss::net::server_base(a_category)
, m_auth_db_filename(a_auth_db)
{
	ss::icr& l_icr = ss::icr::get();

	if (l_icr.key_is_defined(m_category, "banner")) {
		m_banner = l_icr.to_boolean(l_icr.keyvalue(m_category, "banner"));
	}
	// we are in charge of processing user commands, so we configure the auth layer
	bool l_load = load_authdb(m_auth_db_filename);
	ctx.log(std::format("loaded auth_db ({}): {})", m_auth_db_filename, l_load));
}

command_server::~command_server()
{
}

void command_server::shutdown()
{
	ctx.log("Shutting down command_server subsystem..");
	bool l_save = save_authdb(m_auth_db_filename);
	ctx.log(std::format("saved auth_db ({}): {})", m_auth_db_filename, l_save));
	server_base::shutdown();
}

} // namespace net
} // namespace ss
