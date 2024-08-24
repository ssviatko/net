#ifndef COMMAND_SERVER
#define COMMAND_SERVER

#include "server_base.h"
#include "log.h"

namespace ss {
namespace net {

class command_server : public ss::net::server_base {
public:
	command_server();
	~command_server();
	virtual void shutdown();
protected:
	ss::log::ctx& ctx = ss::log::ctx::get();
};

} // namespace net
} // namespace ss

#endif // COMMAND_SERVER
