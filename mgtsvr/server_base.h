#ifndef SERVER_BASE
#define SERVER_BASE

#include "auth.h"

namespace ss {
namespace net {

class server_base : public ss::net::auth {
public:
	server_base();
	~server_base();
};

} // namespace net
} // namespace ss

#endif // SERVER_BASE
