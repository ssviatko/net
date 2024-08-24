#ifndef SERVER_BASE
#define SERVER_BASE

#include <string>
#include <exception>
#include <stdexcept>

#include "icr.h"
#include "auth.h"
#include "log.h"

namespace ss {
namespace net {

class server_base : public ss::net::auth {
public:
	server_base(const std::string& a_category);
	~server_base();
	virtual void shutdown();
protected:
	ss::log::ctx& ctx = ss::log::ctx::get();
	std::string m_category;
};

} // namespace net
} // namespace ss

#endif // SERVER_BASE
