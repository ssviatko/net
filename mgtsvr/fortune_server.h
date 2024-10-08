#ifndef FORTUNE_SERVER
#define FORTUNE_SERVER

#include <string>
#include <vector>

#include "command_server.h"
#include "log.h"

class fortune_server : public ss::net::command_server {
public:
	fortune_server();
	virtual ~fortune_server();
	void external_command(int client_sockfd, std::vector<std::string>& a_cmdv);
	virtual void shutdown();
protected:
	ss::log::ctx& ctx = ss::log::ctx::get();
};

#endif // FORTUNE_SERVER
