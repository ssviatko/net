#include "command_server.h"

namespace ss {
namespace net {

command_server::command_server(const std::string& a_category, const std::string& a_auth_db)
: ss::net::server_base(a_category)
, m_auth_db_filename(a_auth_db)
{
	ctx.log("command_server starting up..");
	ss::icr& l_icr = ss::icr::get();

	if (l_icr.key_is_defined(m_category, "banner")) {
		m_banner = l_icr.to_boolean(l_icr.keyvalue(m_category, "banner"));
		m_banner_file = l_icr.keyvalue(m_category, "banner_file");
	}
	if (l_icr.key_is_defined(m_category, "logon_banner")) {
		m_logon_banner = l_icr.to_boolean(l_icr.keyvalue(m_category, "logon_banner"));
		m_logon_banner_file = l_icr.keyvalue(m_category, "logon_banner_file");
	}
	if (m_banner) {
		ctx.log(std::format("banner ACTIVE, file = {}", m_banner_file));
	}
	if (m_logon_banner) {
		ctx.log(std::format("logon banner ACTIVE, file = {}", m_logon_banner_file));
	}
	// we are in charge of processing user commands, so we configure the auth layer
	bool l_load = load_authdb(m_auth_db_filename);
	ctx.log(std::format("loaded auth_db ({}): {})", m_auth_db_filename, l_load));
	ctx.log("command processor UP");
}

command_server::~command_server()
{
}

void command_server::shutdown()
{
	ctx.log("Shutting down command_server subsystem..");
	bool l_save = save_authdb(m_auth_db_filename);
	ctx.log(std::format("saved auth_db ({}): {})", m_auth_db_filename, l_save));
	ctx.log("command processor DOWN");
	server_base::shutdown();
}

void command_server::newly_accepted_client(int client_sockfd)
{
//	ctx.log(std::format("newly_accepted_client: {}", client_sockfd));
	if (m_logon_banner) {
		ss::data l_logon_banner;
		l_logon_banner.load_file(m_logon_banner_file);
		std::string l_string = l_logon_banner.read_std_str(l_logon_banner.size());
		send_to_client(client_sockfd, l_string);
	}
	if (m_auth_policy > 1) {
		std::lock_guard<std::mutex> l_guard(m_client_list_mtx);
		std::map<int, client_rec>::iterator l_client_list_it = m_client_list.find(client_sockfd);
		// send "username:" string
		send_to_client(client_sockfd, "username: ");
		l_client_list_it->second.m_auth_state = auth_state::AUTH_STATE_AWAIT_USERNAME;
	} else {
		// no logon, just send banner if it is configured
		if (m_banner) {
			ss::data l_banner;
			l_banner.load_file(m_banner_file);
			std::string l_string = l_banner.read_std_str(l_banner.size());
			send_to_client(client_sockfd, l_string);
		}
	}
}

void command_server::send_to_client(int client_sockfd, const std::string& a_string)
{
	// assumes m_client_list_mtx is locked
	std::map<int, client_rec>::iterator l_client_list_it = m_client_list.find(client_sockfd);
	l_client_list_it->second.m_out_circbuff.write_std_str_delim(a_string);
	set_epollout_for_fd(client_sockfd);
}

void command_server::data_from_client(int client_sockfd)
{
	// we are called when a client sockfd has actionable data waiting. Our job is to grab
	// the data piecemeal (as strings in this case) and enqueue if for service.
	// client_list is locked while we are in here, our caller will unlock it.
	std::map<int, client_rec>::iterator l_client_list_it = m_client_list.find(client_sockfd);
	while (l_client_list_it->second.m_in_circbuff.size() > 0) {
		std::optional<std::string> l_data = l_client_list_it->second.m_in_circbuff.read_std_str_delim();
		if (l_data.has_value()) {
			if (l_data.value().size() > 0) {
				command_work_item l_item;
				l_item.client_sockfd = client_sockfd;
				l_item.data = l_data.value();
//				ctx.log(std::format("data_from_client: enqueueing {} from fd {}", l_data.value(), client_sockfd));
				m_queue.add_work_item(l_item);
			}
		} else {
			// stop processing this file descriptor
			break;
		}
	}
}

} // namespace net
} // namespace ss
