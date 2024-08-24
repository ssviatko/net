#ifndef SERVER_BASE
#define SERVER_BASE

#include "auth.h"
#include "log.h"

namespace ss {
namespace net {

class server_base : public ss::net::auth {
public:
	server_base();
	~server_base();
	virtual void shutdown();
protected:
	ss::log::ctx& ctx = ss::log::ctx::get();
};

} // namespace net
} // namespace ss

#endif // SERVER_BASE
