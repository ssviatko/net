#ifndef FORTUNE_SERVER
#define FORTUNE_SERVER

#include "command_server.h"
#include "log.h"

namespace ss {
namespace net {

class fortune_server : public ss::net::command_server {
public:
	fortune_server();
	~fortune_server();
	virtual void shutdown();
protected:
	ss::log::ctx& ctx = ss::log::ctx::get();
};

} // namespace net
} // namespace ss

#endif // FORTUNE_SERVER
