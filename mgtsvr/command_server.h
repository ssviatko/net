#ifndef COMMAND_SERVER
#define COMMAND_SERVER

#include <string>
#include <format>
#include <optional>
#include <thread>
#include <mutex>

#include "icr.h"
#include "server_base.h"
#include "log.h"
#include "ccl.h"

namespace ss {
namespace net {

class command_server : public ss::net::server_base {
public:

	struct command_work_item {
		int client_sockfd;
		std::string data;
	};
	
	command_server(const std::string& a_category, const std::string& a_auth_db);
	virtual ~command_server();
	virtual void shutdown();
	virtual void newly_accepted_client(int client_sockfd);
	virtual void data_from_client(int client_sockfd);
	
protected:
	ss::log::ctx& ctx = ss::log::ctx::get();
	bool m_banner; // should we print the banner when a user logs on?
	std::string m_banner_file;
	bool m_logon_banner;
	std::string m_logon_banner_file;
	std::string m_auth_db_filename;
	ss::ccl::work_queue<command_work_item> m_queue;
	// command server functions
	void send_to_client(int client_sockfd, const std::string& a_string);
	unsigned int m_worker_threads;
	std::mutex m_finish_sem_mutex; // roll your own semaphore, we want to block until it reaches zero
	unsigned int m_finish_sem;
	void worker_thread(const std::string& a_logname);
	void process_command(command_work_item a_item);
};

} // namespace net
} // namespace ss

#endif // COMMAND_SERVER
