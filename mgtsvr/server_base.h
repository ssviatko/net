#ifndef SERVER_BASE
#define SERVER_BASE

#include <string>
#include <exception>
#include <stdexcept>
#include <thread>
#include <chrono>
#include <format>

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/utsname.h>

#include "icr.h"
#include "auth.h"
#include "log.h"
#include "doubletime.h"
#include "dispatchable.h"

namespace ss {
namespace net {

class server_base : public ss::net::auth, public ss::ccl::dispatchable {
public:
	server_base(const std::string& a_category);
	~server_base();
	virtual void shutdown();
	virtual bool dispatch();
	void setup_server();
	void setup_server_un();
	
protected:
	ss::log::ctx& ctx = ss::log::ctx::get();
	std::string m_category;
	ss::doubletime m_uptime;
	
	/* server globals */
	int m_server_sockfd;
	struct sockaddr_in m_server_address;
	int m_server_sockfd_un;
	struct sockaddr_un m_server_address_un;
	int m_epollfd;
};

} // namespace net
} // namespace ss

#endif // SERVER_BASE
