#ifndef COMMAND_SERVER
#define COMMAND_SERVER

#include <string>
#include <format>

#include "icr.h"
#include "server_base.h"
#include "log.h"

namespace ss {
namespace net {

class command_server : public ss::net::server_base {
public:
	command_server(const std::string& a_category, const std::string& a_auth_db);
	~command_server();
	virtual void shutdown();
protected:
	ss::log::ctx& ctx = ss::log::ctx::get();
	bool m_banner; // should we print the banner when a user logs on?
	std::string m_auth_db_filename;
};

} // namespace net
} // namespace ss

#endif // COMMAND_SERVER
