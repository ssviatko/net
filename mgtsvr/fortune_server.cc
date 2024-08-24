#include "fortune_server.h"

namespace ss {
namespace net {

fortune_server::fortune_server()
: ss::net::command_server("fortune_server", "fortune_auth_db")
{
	
}

fortune_server::~fortune_server()
{
	
}

void fortune_server::shutdown()
{
	ctx.log("Shutting down fortune_server subsystem..");
	command_server::shutdown();
}

} // namespace net
} // namespace ss
