#ifndef SERVER_BASE
#define SERVER_BASE

#include <string>
#include <sstream>
#include <exception>
#include <stdexcept>
#include <thread>
#include <mutex>
#include <chrono>
#include <format>
#include <map>
#include <set>
#include <array>
#include <cstdint>
#include <atomic>

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
#include "esr.h"
#include "log.h"
#include "doubletime.h"
#include "dispatchable.h"

namespace ss {
namespace net {

class server_base
: public ss::net::auth
, public ss::esr
, public ss::ccl::dispatchable {
public:
	server_base(const std::string& a_category);
	virtual ~server_base();
	virtual void shutdown();
	bool request_down() { return m_request_down; }
	bool request_hup() { return m_request_hup; }
	virtual bool dispatch();
	void setup_server_tcp();
	void setup_server_un();
	virtual void newly_accepted_client(int client_sockfd) = 0;
	virtual void data_from_client(int client_sockfd) = 0;
	
	const static std::uint32_t DRAIN_BUFFER_SIZE = 16384;
	const static std::uint32_t WRITE_CHUNK_SIZE = 4096;
	
protected:
	enum auth_state {
		AUTH_STATE_NOAUTH,
		AUTH_STATE_AWAIT_USERNAME,
		AUTH_STATE_AWAIT_PASSWORD,
		AUTH_STATE_AWAIT_CHAL,
		AUTH_STATE_LOGGED_ON
	};
	
	struct client_rec {
		auth_state m_auth_state;
		std::string m_auth_username;
		challenge_pack m_auth_challenge_pack;
		sa_family_t m_family;
		struct sockaddr_in m_sockaddr_in;
		struct sockaddr_un m_sockaddr_un;
		ss::doubletime m_connect_time;
		ss::data m_in_circbuff;
		ss::data m_out_circbuff;
	};

	ss::log::ctx& ctx = ss::log::ctx::get();
	std::string m_category;
	int m_auth_policy;
	ss::doubletime m_uptime;
	std::atomic<bool> m_request_down;
	std::atomic<bool> m_request_hup;
	
	// server functions
	void set_epollout_for_fd(int a_fd);
	void flushout(int client_sockfd);
	void serve();
	void drain_socket(int client_sockfd);
	int accept_client(int a_server_fd);
	void remove_client(int client_sockfd);
	std::string ip_str(const struct sockaddr_in *a_addr);
	std::string un_str(const struct sockaddr_un *a_addr);
	
	/* server globals */
	int m_server_sockfd;
	struct sockaddr_in m_server_address;
	int m_server_sockfd_un;
	struct sockaddr_un m_server_address_un;
	int m_epollfd;
	
	// these exist so we don't have to iterate the whole client_list to see if we have data waiting on a particular fd
	std::set<int> m_input_hints; // list of fd's with input data waiting to be processed

	// the client list and her mutex
	std::map<int, client_rec> m_client_list;
	std::mutex m_client_list_mtx;
};

} // namespace net
} // namespace ss

#endif // SERVER_BASE
