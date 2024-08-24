#include "command_server.h"

namespace ss {
namespace net {

command_server::command_server()
{
	
}

command_server::~command_server()
{
	
}

void command_server::shutdown()
{
	ctx.log("Shutting down command_server subsystem..");
	server_base::shutdown();
}

} // namespace net
} // namespace ss
