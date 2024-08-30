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
	ctx.log(std::format("server DOWN (up for {} seconds)", ss::doubletime::now_as_double() - double(m_uptime)));
}

bool server_base::dispatch()
{
	struct epoll_event events[100];
	int n = epoll_wait(m_epollfd, events, 100, 20);
	if (n == 0) {
		// housekeeping tasks while waiting for data go here
		return true;
	}
	bool l_did_input = false;
	while (n-- > 0) {
		if (events[n].events & EPOLLIN) {
			if ((events[n].data.fd == m_server_sockfd) || (events[n].data.fd == m_server_sockfd_un)) {
				// accept connection
				int l_client = accept_client(events[n].data.fd);
				if (l_client == -1) {
					ctx.log_p(ss::log::ERR, std::format("error accepting client at: {}", ss::doubletime::now_as_iso8601_ms()));
					continue;
				} else {
					// client accepted successfully
//					ctx.log_p(ss::log::INFO, std::format("accepted client at: {} on fd {}", ss::doubletime::now_as_iso8601_ms(), l_client));
					newly_accepted_client(l_client);
				}
			} else {
				// EPOLLIN on a client socket
				int client_sockfd = events[n].data.fd;
//				std::cout << "EPOLLIN on " << client_sockfd << std::endl;
				drain_socket(client_sockfd);
				l_did_input = true;
			}
		} else if (events[n].events & EPOLLHUP) {
			int client_sockfd = events[n].data.fd;
//			std::cout << "EPOLLHUP on " << client_sockfd << std::endl;
			// had a client hang up, so remove its connection
			remove_client(client_sockfd);
		} else if (events[n].events & EPOLLOUT) {
			// EPOLLOUT on a client socket
			flushout(events[n].data.fd);
		}
	}
	if (l_did_input)
		serve();

	return true;
}

void server_base::flushout(int client_sockfd)
{
	std::lock_guard<std::mutex> l_guard(m_client_list_mtx);
	// find our client record
	std::map<int, client_rec>::iterator l_client_list_it = m_client_list.find(client_sockfd);
	int l_datalen = l_client_list_it->second.m_out_circbuff.size();
	// write in chunks
	int l_towrite = (l_datalen >(int)WRITE_CHUNK_SIZE) ? WRITE_CHUNK_SIZE : l_datalen;
	int l_ret = write(client_sockfd, l_client_list_it->second.m_out_circbuff.buffer(), l_towrite);
	if (l_ret < 0) {
		// error
		ctx.log_p(ss::log::WARNING, std::format("possible error writing to fd: {} - {}", client_sockfd, strerror(errno)));
		return;
	} else if (l_ret == 0) {
		// EOF
		ctx.log(std::format("possible EOF writing to fd: {}", client_sockfd));
		return;
	} else if (l_ret < l_towrite) {
		// partial write... (why?)
		ctx.log(std::format("wrote {} bytes to fd: {}, expected to write {}", l_ret, client_sockfd, l_towrite));
	} else if (l_ret == l_towrite) {
		// all bytes written
	}

	l_client_list_it->second.m_out_circbuff.truncate_front(l_ret);

	if (l_client_list_it->second.m_out_circbuff.size() == 0) {
		// we emptied it, so clear EPOLLOUT flag for fd
//		log << ulog::debug << "dispatch: clearing EPOLLOUT for fd:" << client_sockfd << std::endl;
		struct epoll_event l_client_info;
		l_client_info.events = EPOLLIN | EPOLLHUP;
		l_client_info.data.fd = client_sockfd;
		epoll_ctl(m_epollfd, EPOLL_CTL_MOD, client_sockfd, &l_client_info);
	}
}

void server_base::set_epollout_for_fd(int a_fd)
{
	struct epoll_event l_client_info;
	l_client_info.events = EPOLLIN | EPOLLHUP | EPOLLOUT;
	l_client_info.data.fd = a_fd;
	epoll_ctl(m_epollfd, EPOLL_CTL_MOD, a_fd, &l_client_info);
}

void server_base::serve()
{
	// iterate input hints set and execute waiting commands for each client
	std::lock_guard<std::mutex> l_guard(m_client_list_mtx);
	std::set<int>::iterator l_input_hints_it = m_input_hints.begin();
	while (l_input_hints_it != m_input_hints.end()) {
		int l_curfd = (*l_input_hints_it);
		data_from_client(l_curfd);
		++l_input_hints_it;
	}
	m_input_hints.clear();
}

void server_base::drain_socket(int client_sockfd)
{
	std::array<std::uint8_t, DRAIN_BUFFER_SIZE> l_buffer;
	int l_readbytes = read(client_sockfd, l_buffer.data(), DRAIN_BUFFER_SIZE);
//	ctx.log(std::format("read {} bytes from fd: {}", l_readbytes, client_sockfd));
	if (l_readbytes <= 0) {
		// EOF
		remove_client(client_sockfd);
	} else {
		// stick the data in client's input circular buffer
		m_client_list_mtx.lock();
		std::map<int, client_rec>::iterator client_list_it = m_client_list.find(client_sockfd);
		client_list_it->second.m_in_circbuff.assign(l_buffer.data(), l_readbytes);
		m_input_hints.insert(client_sockfd);
		m_client_list_mtx.unlock();
	}
}


int server_base::accept_client(int a_server_fd)
{
	client_rec l_rec;
	l_rec.m_auth_state = auth_state::AUTH_STATE_NOAUTH;
	l_rec.m_auth_username = "";
	l_rec.m_in_circbuff.set_circular_mode(true);
	l_rec.m_out_circbuff.set_circular_mode(true);
	socklen_t client_len;
	int client_sockfd = 0;
	struct sockaddr_in client_address;
	struct sockaddr_un client_address_un;
	if (a_server_fd == m_server_sockfd) {
		client_len = sizeof(client_address);
		client_sockfd = accept4(m_server_sockfd, (struct sockaddr *)&client_address, &client_len, SOCK_NONBLOCK);
		if (client_sockfd == -1) return -1; // some error accepting so just keep on going
		l_rec.m_family = AF_INET;
		l_rec.m_sockaddr_in = client_address;
	} else if (a_server_fd == m_server_sockfd_un) {
		client_len = sizeof(client_address_un);
		client_sockfd = accept4(m_server_sockfd_un, (struct sockaddr *)&client_address_un, &client_len, SOCK_NONBLOCK);
		if (client_sockfd == -1) return -1;
		l_rec.m_family = AF_UNIX;
		l_rec.m_sockaddr_un = client_address_un;
	}
	// build client record
	l_rec.m_connect_time.now();
	m_client_list_mtx.lock();
	m_client_list.insert(std::pair<int, client_rec>(client_sockfd, l_rec));
	// add socket to epoll
	struct epoll_event l_client_info;
	l_client_info.events = EPOLLIN | EPOLLHUP;
	l_client_info.data.fd = client_sockfd;
	epoll_ctl(m_epollfd, EPOLL_CTL_ADD, client_sockfd, &l_client_info);
	m_client_list_mtx.unlock();

	switch (l_rec.m_family) {
		case AF_INET:
			ctx.log_p(ss::log::INFO, std::format("accepted TCP client fd: {} ({}) at: {}", client_sockfd, ip_str(&l_rec.m_sockaddr_in), l_rec.m_connect_time.iso8601_ms()));
			break;
		case AF_UNIX:
			ctx.log_p(ss::log::INFO, std::format("accepted UNIX client fd: {} ({}) at: {}", client_sockfd, un_str(&l_rec.m_sockaddr_un), l_rec.m_connect_time.iso8601_ms()));
			break;
	}
	return client_sockfd;
}

void server_base::remove_client(int client_sockfd)
{
	std::lock_guard<std::mutex> l_guard(m_client_list_mtx);
	close(client_sockfd);
	// remove from epoll
	struct epoll_event l_client_info;
	l_client_info.events = 0;
	epoll_ctl(m_epollfd, EPOLL_CTL_DEL, client_sockfd, &l_client_info);
	std::map<int, client_rec>::iterator client_list_it = m_client_list.find(client_sockfd);
	double l_ct = double(client_list_it->second.m_connect_time);
	switch (client_list_it->second.m_family) {
		case AF_INET:
			ctx.log_p(ss::log::INFO, std::format("disconnected TCP client fd: {} ({}) at: {} connected for {} seconds.", client_sockfd, ip_str(&client_list_it->second.m_sockaddr_in), ss::doubletime::now_as_iso8601_ms(), ss::doubletime::now_as_double() - l_ct));
			break;
		case AF_UNIX:
			ctx.log_p(ss::log::INFO, std::format("disconnected UNIX client fd: {} ({}) at: {} connected for {} seconds.", client_sockfd, un_str(&client_list_it->second.m_sockaddr_un), ss::doubletime::now_as_iso8601_ms(), ss::doubletime::now_as_double() - l_ct));
			break;
	}
	m_client_list.erase(client_list_it);
	// remove client_sockfd from hints list
	m_input_hints.erase(client_sockfd);
}

std::string server_base::ip_str(const struct sockaddr_in *a_addr)
{
	std::stringstream l_ss;
	std::string l_host = std::string(inet_ntoa(a_addr->sin_addr));
	l_ss << l_host << ":" << ntohs(a_addr->sin_port);
	return l_ss.str();
}

std::string server_base::un_str(const struct sockaddr_un *a_addr)
{
//	ss::data l_sun_path;
//	l_sun_path.emplace((std::uint8_t *)a_addr->sun_path, 14);
//	std::string l_host = l_sun_path.read_hex_str(14);
//	return l_host;

	// contents of client side sockaddr_un appear to be gibberish?
	return "UNIX socket connection";
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
