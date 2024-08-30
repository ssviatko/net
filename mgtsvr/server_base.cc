#include "server_base.h"

namespace ss {
namespace net {

server_base::server_base(const std::string& a_category)
: ss::net::auth(ss::net::auth::role::SERVER)
, ss::ccl::dispatchable(a_category + "_basedisp")
, m_category(a_category)
{
	ss::icr& l_icr = ss::icr::get();

	if (!l_icr.key_is_defined(m_category, "port")) {
		ctx.log_p(ss::log::NOTICE, "key <port> must be defined in ini file, exiting!");
		throw std::runtime_error("server_base: key <port> must be defined in ini file, exiting!");
	}
	if (!l_icr.key_is_defined(m_category, "unix_socket")) {
		ctx.log_p(ss::log::NOTICE, "key <unix_socket> must be defined in ini file, exiting!");
		throw std::runtime_error("server_base: key <unix_socket> must be defined in ini file, exiting!");
	}
	if (!l_icr.key_is_defined(m_category, "enable_tcp")) {
		ctx.log_p(ss::log::NOTICE, "key <enable_tcp> must be defined in ini file, exiting!");
		throw std::runtime_error("server_base: key <enable_tcp> must be defined in ini file, exiting!");
	}
	if (!l_icr.key_is_defined(m_category, "enable_unix")) {
		ctx.log_p(ss::log::NOTICE, "key <enable_unix> must be defined in ini file, exiting!");
		throw std::runtime_error("server_base: key <enable_unix> must be defined in ini file, exiting!");
	}

	bool l_enable_tcp = l_icr.to_boolean(l_icr.keyvalue(m_category, "enable_tcp"));
	bool l_enable_unix = l_icr.to_boolean(l_icr.keyvalue(m_category, "enable_unix"));
	// got to have one or the other, can't disable both of them
	if (!l_enable_tcp && !l_enable_unix) {
		ctx.log_p(ss::log::NOTICE, "one or both of the available listening methods must be enabled, exiting!");
		throw std::runtime_error("server_base: one or both of the available listening methods must be enabled, exiting!");
	}
	
	// init epoll
	if ((m_epollfd = epoll_create(50)) == -1) {
		ctx.log_p(ss::log::NOTICE, std::format("unable to initialize epoll, errno = {} ({}), exiting!", errno, strerror(errno)));
		throw std::runtime_error("server_base: unable to initialize epoll, exiting!");
	}
	ctx.log(std::format("initialized epoll, fd = {}", m_epollfd));
	
	// init the server
	if (l_enable_tcp) {
		ctx.log_p(ss::log::INFO, "starting TCP server..");
		setup_server();
	}
	
	if (l_enable_unix) {
		ctx.log_p(ss::log::INFO, "starting UNIX socket server..");
		setup_server_un();
	}
	
	start();
	m_uptime.now();
	ctx.log_p(ss::log::INFO, "server UP");
}

server_base::~server_base()
{
	
}

void server_base::shutdown()
{
	ctx.log("Shutting down server_base subsystem..");
	halt();
	close(m_epollfd);
	close(m_server_sockfd);
	close(m_server_sockfd_un);
}

bool server_base::dispatch()
{
	std::this_thread::sleep_for(std::chrono::seconds(1));
	ctx.log("server_base::dispatch: doing nothing and loving it");
	return true;
}

void server_base::setup_server()
{
	int listen_port;
	int backlog = 5;

	ss::icr& l_icr = ss::icr::get();
	listen_port = l_icr.to_integer(l_icr.keyvalue(m_category, "port"));
	ctx.log(std::format("setup_server: setting port to {}", listen_port));

	// remove any old sockets and create an unnamed socket for the server
	m_server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (m_server_sockfd == -1) {
		ctx.log_p(ss::log::ERR, "setup_server: socket() call failed, exiting!");
		throw std::runtime_error("setup_server: socket() call failed, exiting!");
	}

	// make server socket nonblocking
	int server_sockfd_flags = fcntl(m_server_sockfd, F_GETFL);
	server_sockfd_flags |= O_NONBLOCK;
	if (fcntl(m_server_sockfd, F_SETFL, server_sockfd_flags) == -1) {
		ctx.log_p(ss::log::ERR, "setup_server: unable to set server_sockfd flags, exiting!");
		throw std::runtime_error("setup_server: unable to set server_sockfd flags, exiting!");
	}

	// add server socket to epoll
	struct epoll_event ev;
	ev.events = EPOLLIN | EPOLLRDHUP;
	ev.data.fd = m_server_sockfd;
	if (epoll_ctl(m_epollfd, EPOLL_CTL_ADD, m_server_sockfd, &ev) == -1) {
		ctx.log_p(ss::log::ERR, std::format("setup_server: unable to add server socket to epoll, errno = {} ({}), exiting!", errno, strerror(errno)));
		throw std::runtime_error("setup_server: unable to add server socket to epoll, exiting!");
	}

	// name the socket
	m_server_address.sin_family = AF_INET;
	m_server_address.sin_addr.s_addr = htonl(INADDR_ANY);
	m_server_address.sin_port = htons(listen_port);
	int server_len = sizeof(m_server_address);
	int reuse = 1;

	if (setsockopt(m_server_sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) < 0) {
		ctx.log_p(ss::log::ERR, "setup_server: setsockopt SO_REUSEADDR returned error, exiting!");
		close(m_server_sockfd);
		throw std::runtime_error("setup_server: setsockopt SO_REUSEADDR returned error, exiting!");
	}
	ctx.log("setup_server: set reuse");

	if (bind(m_server_sockfd, (struct sockaddr *)&m_server_address, server_len) != 0)
	{
		ctx.log_p(ss::log::ERR, "setup_server: bind failed, exiting!");
		throw std::runtime_error("setup_server: bind failed, exiting!");
	}

	if (listen(m_server_sockfd, backlog) < 0) {
		ctx.log_p(ss::log::ERR, "setup_server: listen failed, exiting!");
		throw std::runtime_error("setup_server: listen failed, exiting!");
	}

	ctx.log(std::format("setup_server: server_sockfd = {}", m_server_sockfd));
}

void server_base::setup_server_un()
{
	int backlog = 5;
	ss::icr& l_icr = ss::icr::get();

	// remove any old sockets and create an unnamed socket for the server
	m_server_sockfd_un = socket(AF_UNIX, SOCK_STREAM, 0);
	if (m_server_sockfd_un == -1) {
		ctx.log_p(ss::log::ERR, "setup_server_un: socket() call failed, exiting!");
		throw std::runtime_error("setup_server_un: socket() call failed, exiting!");
	}

	// make server socket nonblocking
	int server_sockfd_flags = fcntl(m_server_sockfd_un, F_GETFL);
	server_sockfd_flags |= O_NONBLOCK;
	if (fcntl(m_server_sockfd_un, F_SETFL, server_sockfd_flags) == -1) {
		ctx.log_p(ss::log::ERR, "setup_server_un: unable to set server_sockfd flags, exiting!");
		throw std::runtime_error("setup_server_un: unable to set server_sockfd flags, exiting!");
	}

	// add server socket to epoll
	struct epoll_event ev;
	ev.events = EPOLLIN | EPOLLRDHUP;
	ev.data.fd = m_server_sockfd_un;
	if (epoll_ctl(m_epollfd, EPOLL_CTL_ADD, m_server_sockfd_un, &ev) == -1) {
		ctx.log_p(ss::log::ERR, std::format("setup_server: unable to add server socket to epoll, errno = {} ({}), exiting!", errno, strerror(errno)));
		throw std::runtime_error("setup_server_un: unable to add server socket to epoll, exiting!");
	}

	// name the socket
	m_server_address_un.sun_family = AF_UNIX;
	std::string l_sockname = l_icr.keyvalue(m_category, "unix_socket");
	strcpy(m_server_address_un.sun_path, l_sockname.c_str());
	int server_len = sizeof(m_server_address);
	unlink(l_sockname.c_str());

	if (bind(m_server_sockfd_un, (struct sockaddr *)&m_server_address_un, server_len) != 0)
	{
		ctx.log_p(ss::log::ERR, "setup_server_un: bind failed, exiting!");
		throw std::runtime_error("setup_server_un: bind failed, exiting!");
	}

	if (listen(m_server_sockfd_un, backlog) < 0) {
		ctx.log_p(ss::log::ERR, "setup_server_un: listen failed, exiting!");
		throw std::runtime_error("setup_server_un: listen failed, exiting!");
	}

	ctx.log(std::format("setup_server_un: server_sockfd_un = {}", m_server_sockfd_un));
}

} // namespace net
} // namespace ss
