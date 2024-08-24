#include "server_base.h"

namespace ss {
namespace net {

server_base::server_base()
: ss::net::auth(ss::net::auth::role::SERVER)
{
	
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
