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
	if (!l_load) {
		// if we didn't load the auth db (i.e. we're starting from scratch), create some default accounts
		bool l_add_user_success;
		l_add_user_success = add_user_plaintext_pw("ssviatko", "banana");
		ctx.log(std::format("add default user ssviatko: {}", l_add_user_success));
		l_add_user_success = add_user_plaintext_pw("admin", "admin");
		set_priv_level("admin", -1);
		ctx.log(std::format("add default user admin: {}", l_add_user_success));
		l_add_user_success = add_user_plaintext_pw("operator", "operator");
		set_priv_level("operator", -2);
		ctx.log(std::format("add default user operator: {}", l_add_user_success));
		l_add_user_success = add_user_plaintext_pw("chump", "chump");
		set_priv_level("chump", 1);
		ctx.log(std::format("add default user chump: {}", l_add_user_success));
	}
	
	// prompts
	if (!l_icr.key_is_defined(m_category, "prompts")) {
		ctx.log_p(ss::log::ERR, "key <prompts> must be defined in ini file, exiting!");
		throw std::runtime_error("command_server: key <prompts> must be defined in ini file, exiting!");
	}
	m_prompts = l_icr.to_boolean(l_icr.keyvalue(m_category, "prompts"));

	// start worker threads
	if (!l_icr.key_is_defined(m_category, "worker_threads")) {
		ctx.log_p(ss::log::ERR, "key <worker_threads> must be defined in ini file, exiting!");
		throw std::runtime_error("command_server: key <worker_threads> must be defined in ini file, exiting!");
	}
	m_worker_threads = l_icr.to_integer(l_icr.keyvalue(m_category, "worker_threads"));
	// sanity check number of worker threads
	if ((m_worker_threads > 32) || (m_worker_threads == 0)) {
		ctx.log_p(ss::log::ERR, "key <worker_threads> can be set to a maximum of 32 and may not be zero.");
		throw std::runtime_error("command_server: key <worker_threads> can be set to a maximum of 32 and may not be zero.");
	}
	m_finish_sem_mutex.lock();
	m_finish_sem = 0;
	for (std::size_t i = 1; i <= m_worker_threads; ++i) {
		std::string l_name = std::format("{}_work{}", m_category, i);
		std::thread l_work_thr(&command_server::worker_thread, this, l_name);
		l_work_thr.detach();
		m_finish_sem++;
	}
	m_finish_sem_mutex.unlock();

	ctx.log("command processor UP");
}

command_server::~command_server()
{
}

void command_server::shutdown()
{
	ctx.log("Shutting down command_server subsystem..");

	// tell everybody we're shutting down
	std::set<int> l_clients;
	// grab list of connected clients
	m_client_list_mtx.lock();
	for (auto& [key, value] : m_client_list)
		l_clients.insert(key);
	m_client_list_mtx.unlock();
	// iterate the set and send out the broadcast
	for (auto& i : l_clients) {
		lock_client_output(i);
		send_to_client_atomic(i, "[command_server: system is shutting down immediately]");
		send_to_client_atomic(i, "disconnecting...");
		unlock_client_output(i);
	}

	// shut down the work queue - no more command execution at this point
	m_queue.shut_down();
	// wait for worker threads to finish up
	do {
		m_finish_sem_mutex.lock();
//		std::cout << "m_finish_sem is " << m_finish_sem << std::endl;
		if (m_finish_sem == 0) {
			m_finish_sem_mutex.unlock();
			break;
		}
		m_finish_sem_mutex.unlock();
		// wait a bit
		std::this_thread::sleep_for(std::chrono::milliseconds(20));
	} while (1);
	ctx.log("Worker threads completed.");

	// log everybody off
	for (auto& [key, value] : m_user_records) {
		auto l_logged_in = logged_in(key);
		if (l_logged_in.value())
			logout(key);
	}

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
		// send "username:" string
		send_to_client(client_sockfd, "username: ");
		m_client_list_mtx.lock();
		std::map<int, client_rec>::iterator l_client_list_it = m_client_list.find(client_sockfd);
		l_client_list_it->second.m_auth_state = auth_state::AUTH_STATE_AWAIT_USERNAME;
		m_client_list_mtx.unlock();
	} else {
		// no logon, just send banner if it is configured
		if (m_banner) {
			ss::data l_banner;
			l_banner.load_file(m_banner_file);
			std::string l_string = l_banner.read_std_str(l_banner.size());
			send_to_client(client_sockfd, l_string);
		}
		prompt(client_sockfd);
	}
}

void command_server::lock_client_output(int client_sockfd)
{
	ACQUIRE_CL(client_sockfd)
}

void command_server::unlock_client_output(int client_sockfd)
{
	RELEASE_CL
}

void command_server::send_to_client(int client_sockfd, const std::string& a_string)
{
	ACQUIRE_CL(client_sockfd)
	l_client_list_it->second.m_out_circbuff.write_std_str_delim(a_string);
	set_epollout_for_fd(client_sockfd);
	RELEASE_CL
}

void command_server::send_to_client_atomic(int client_sockfd, const std::string& a_string)
{
	// same as above, but without locking the client's output mutex.
	// this is so multiple sends can be done in one atomic operation.
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

void command_server::worker_thread(const std::string& a_logname)
{
	ctx.register_thread(a_logname);
	ctx.log_p(ss::log::INFO, std::format("worker thread started up."));
	
	while (!m_queue.is_shut_down()) {
		std::optional<command_work_item> l_item = m_queue.wait_for_item(20);
		if (l_item.has_value()) {
			try {
				bool l_terminal = process_command(l_item.value());
				if (!l_terminal)
					prompt(l_item.value().client_sockfd);
			} catch (std::exception& e) {
				ctx.log_p(ss::log::NOTICE, std::format("unable to process command for user on fd {}. Reason: {}", l_item.value().client_sockfd, e.what()));
			}
		}
	}
	m_finish_sem_mutex.lock();
	m_finish_sem--;
	m_finish_sem_mutex.unlock();
	ctx.log_p(ss::log::INFO, std::format("worker thread exiting..."));
}

std::vector<std::string> command_server::split_command(const std::string& a_command)
{
	std::vector<std::string> l_ret;
	enum { COLLECT, QUOTED, SPLIT } l_state;
	std::string l_current;
	std::string l_str = a_command;
	icr::get().trim_std_string(l_str);
	l_str += " "; // tack a space on the end of our work string to make it easier on our state machine

	l_state = COLLECT;
	for (unsigned int i = 0; i < l_str.size(); ++i) {
		char l_next = l_str[i];
		if (l_state == COLLECT) {
			if (l_next == '\"') {
				// discard quote character and switch to quote mode
				l_state = QUOTED;
			} else if (l_next == ' ') {
				// split character, trim current string and insert it into vector
				l_ret.push_back(l_current);
				l_current = "";
				l_state = COLLECT;
			} else {
				// append this character
				l_current += l_next;
			}
		} else if (l_state == QUOTED) {
			if (l_next == '\"') {
				// discard quote character and switch back to collect mode
				l_state = COLLECT;
			} else {
				// append this character, even if it is a space
				l_current += l_next;
			}
		}
	}
	return l_ret;
}

std::string command_server::pad(const std::string& a_string, std::size_t a_len)
{
	std::string l_ret;
	for (std::size_t i = 0; i < a_len; ++i)
		l_ret += ' ';
	l_ret = a_string + l_ret;
	return l_ret.substr(0, a_len);
}

void command_server::prompt(int client_sockfd)
{
	if (m_prompts) {
		ACQUIRE_CL(client_sockfd)
		std::string l_user = l_client_list_it->second.m_auth_username;
		auth_state l_as = l_client_list_it->second.m_auth_state;
		RELEASE_CL
		// don't show prompt during the login roll...
		if ((l_as != auth_state::AUTH_STATE_NOAUTH) && (l_as != auth_state::AUTH_STATE_LOGGED_ON))
			return;
		if (!(l_as == auth_state::AUTH_STATE_LOGGED_ON))
			l_user = "(non)";
		lock_client_output(client_sockfd);
		send_to_client_atomic(client_sockfd, std::format("\n[{} {}]", m_category, ss::doubletime::now_as_iso8601_ms()));
		send_to_client_atomic(client_sockfd, std::format("{}: please enter a command.", l_user));
		unlock_client_output(client_sockfd);
	}
}

bool command_server::process_command(command_work_item a_item)
{
	ctx.log(std::format("processing command from fd {}, cmd = {}", a_item.client_sockfd, a_item.data));

	// eheck if we're even an authorized user
	ACQUIRE_CL(a_item.client_sockfd)
	auth_state l_as = l_client_list_it->second.m_auth_state;
	RELEASE_CL
	if (l_as == auth_state::AUTH_STATE_NOAUTH) {
		// a non! make sure this is ok
		if (m_auth_policy >= 2) {
			// can't be a non on here if we're requiring logins, so kick this asshole off
			ctx.log_p(ss::log::NOTICE, std::format("Discovered non-user online on fd {} when auth_policy requires logins. Disconnecting user", a_item.client_sockfd));
			remove_client(a_item.client_sockfd);
			return true;
		}
	} else if (l_as == auth_state::AUTH_STATE_AWAIT_USERNAME) {
		// user already logged on?
		auto l_logged_in = logged_in(a_item.data);
		if (l_logged_in.has_value()) {
			if (l_logged_in.value()) { // check these in succession to prevent a bad option exception
				send_to_client(a_item.client_sockfd, "[user already logged in]");
				send_to_client(a_item.client_sockfd, "disconnecting...");
				std::this_thread::sleep_for(std::chrono::milliseconds(500));
				ctx.log_p(ss::log::NOTICE, std::format("user {} attempted multiple logons, disconnecting", a_item.data));
				remove_client(a_item.client_sockfd);
				return true;
			}
		}
		// this user entered username, so process it
		if (m_auth_policy == 2) {
			// ask user for password
			ctx.log_p(ss::log::NOTICE, std::format("user {} attempting logon", a_item.data));
			// send "password:" string
			send_to_client(a_item.client_sockfd, "password: ");
			ACQUIRE_CL(a_item.client_sockfd)
			l_client_list_it->second.m_auth_username = a_item.data;
			l_client_list_it->second.m_auth_state = auth_state::AUTH_STATE_AWAIT_PASSWORD;
			RELEASE_CL
			return false;
		} else if (m_auth_policy == 3) {
			ctx.log_p(ss::log::NOTICE, std::format("user {} attempting logon", a_item.data));
			// send user a session hash and challenge them
			std::optional<challenge_pack> l_pack = challenge(a_item.data);
			if (!l_pack.has_value()) {
				// no such user
				send_to_client(a_item.client_sockfd, "[no such user]");
				send_to_client(a_item.client_sockfd, "disconnecting...");
				std::this_thread::sleep_for(std::chrono::milliseconds(500));
				ctx.log_p(ss::log::NOTICE, std::format("no such user {} found in auth database, disconnecting user", a_item.data));
				remove_client(a_item.client_sockfd);
				return true;
			}
			ACQUIRE_CL(a_item.client_sockfd)
			l_client_list_it->second.m_auth_username = a_item.data;
			// record the challenge pack so we can reference it later
			l_client_list_it->second.m_auth_challenge_pack = l_pack.value();
			l_client_list_it->second.m_auth_state = auth_state::AUTH_STATE_AWAIT_CHAL;
			RELEASE_CL
			// send "session:" string
			send_to_client(a_item.client_sockfd, std::format("session: {}", l_pack.value().session));
			return false;
		}
	} else if (l_as == auth_state::AUTH_STATE_AWAIT_PASSWORD) {
		ACQUIRE_CL(a_item.client_sockfd)
		std::string l_user = l_client_list_it->second.m_auth_username;
		RELEASE_CL
		// if auth_policy is set to 2, we will wind up here after user enters plaintext password
		std::optional<challenge_pack> l_pack = challenge(l_user);
		if (!l_pack.has_value()) {
			// no such user
			send_to_client(a_item.client_sockfd, "[no such user]");
			send_to_client(a_item.client_sockfd, "disconnecting...");
			std::this_thread::sleep_for(std::chrono::milliseconds(500));
			ctx.log_p(ss::log::NOTICE, std::format("no such user {} found in auth database, disconnecting user", l_user));
			remove_client(a_item.client_sockfd);
			return true;
		}
		auth l_dummy_client(auth::role::CLIENT);
		std::optional<std::string> l_response = l_dummy_client.challenge_response(l_pack.value().session, a_item.data);
		if (!l_response.has_value()) {
			// should never happen
			ctx.log_p(ss::log::NOTICE, "unable to generate challenge_response!");
			return true;
		}
		bool l_authenticated = authenticate(l_user, l_pack.value(), l_response.value());
		if (l_authenticated) {
			ctx.log_p(ss::log::INFO, std::format("authenticated user {}", l_user));
			if (m_banner) {
				ss::data l_banner;
				l_banner.load_file(m_banner_file);
				std::string l_string = l_banner.read_std_str(l_banner.size());
				send_to_client(a_item.client_sockfd, l_string);
			}
			{
				ACQUIRE_CL(a_item.client_sockfd)
				l_client_list_it->second.m_auth_state = auth_state::AUTH_STATE_LOGGED_ON;
				RELEASE_CL
			}
			return false;
		} else {
			// not authenticated
			send_to_client(a_item.client_sockfd, "[unable to authenticate]");
			send_to_client(a_item.client_sockfd, "disconnecting...");
			std::this_thread::sleep_for(std::chrono::milliseconds(500));
			ctx.log_p(ss::log::INFO, std::format("unable to authenticate user {}", l_user));
			remove_client(a_item.client_sockfd);
			return true;
		}
	} else if (l_as == auth_state::AUTH_STATE_AWAIT_CHAL) {
		// auth_policy 3: user has accepted our challenge and sent his reply hash
//		std::cout << "expected_response " << l_client_list_it->second.m_auth_challenge_pack.expected_response << " actual response: " << a_item.data << std::endl;
		ACQUIRE_CL(a_item.client_sockfd)
		std::string l_user = l_client_list_it->second.m_auth_username;
		challenge_pack l_pack = l_client_list_it->second.m_auth_challenge_pack;
		RELEASE_CL
		bool l_authenticated = authenticate(l_user, l_pack, a_item.data);
		if (l_authenticated) {
			ctx.log_p(ss::log::INFO, std::format("authenticated user {}", l_user));
			if (m_banner) {
				ss::data l_banner;
				l_banner.load_file(m_banner_file);
				std::string l_string = l_banner.read_std_str(l_banner.size());
				send_to_client(a_item.client_sockfd, l_string);
			}
			{
				ACQUIRE_CL(a_item.client_sockfd)
				l_client_list_it->second.m_auth_state = auth_state::AUTH_STATE_LOGGED_ON;
				RELEASE_CL
			}
			return false;
		} else {
			// not authenticated
			send_to_client(a_item.client_sockfd, "[unable to authenticate]");
			send_to_client(a_item.client_sockfd, "disconnecting...");
			std::this_thread::sleep_for(std::chrono::milliseconds(500));
			ctx.log_p(ss::log::INFO, std::format("unable to authenticate user {}", l_user));
			remove_client(a_item.client_sockfd);
			return true;
		}
	}

	auto l_cmdv = split_command(a_item.data);
	bool l_internal = (l_cmdv[0].at(0) == '/');
	if (l_internal)
		l_cmdv[0].erase(l_cmdv[0].begin()); // hack off forward slash
	for (auto& c : l_cmdv[0]) // make uppercase
		c = std::toupper(c);
	if (!l_internal) {
		external_command(a_item.client_sockfd, l_cmdv);
		return false;
	}
	
	std::string l_user;
	{
		ACQUIRE_CL(a_item.client_sockfd)
		if (l_as == auth_state::AUTH_STATE_LOGGED_ON)
			l_user = l_client_list_it->second.m_auth_username;
		else
			l_user = "(non)";
		RELEASE_CL
	}
	
	if (l_cmdv[0] == "EXIT") {
		// preform logoff
		send_to_client(a_item.client_sockfd, "[logging you off]");
		send_to_client(a_item.client_sockfd, "disconnecting...");
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
		if (m_auth_policy >= 1 && l_as == auth_state::AUTH_STATE_LOGGED_ON) {
			ctx.log_p(ss::log::INFO, std::format("logging off user {}", l_user));
			logout(l_user);
		}
		remove_client(a_item.client_sockfd);
		return true;
	}
	if (l_cmdv[0] == "WHOAMI") {
		if (l_as == auth_state::AUTH_STATE_LOGGED_ON) {
			ACQUIRE_CL(a_item.client_sockfd)
			ss::doubletime l_conn_time = l_client_list_it->second.m_connect_time;
			RELEASE_CL
			lock_client_output(a_item.client_sockfd);
			send_to_client_atomic(a_item.client_sockfd, std::format("{}{}", pad("you are:", 20), l_user));
			auto l_priv = priv_level(l_user);
			send_to_client_atomic(a_item.client_sockfd, std::format("{}{}", pad("privilege level:", 20), l_priv.value()));
			auto l_last_login = last_login(l_user);
			send_to_client_atomic(a_item.client_sockfd, std::format("{}{}", pad("last login:", 20), l_last_login.value().iso8601_ms()));
			auto l_last = last(l_user);
			send_to_client_atomic(a_item.client_sockfd, std::format("{}{}", pad("last seen:", 20), l_last.value().iso8601_ms()));
			auto l_creation = creation(l_user);
			send_to_client_atomic(a_item.client_sockfd, std::format("{}{}", pad("account creation:", 20), l_creation.value().iso8601_ms()));
			send_to_client_atomic(a_item.client_sockfd, std::format("{}{}", pad("connected on:", 20), l_conn_time.iso8601_ms()));
			send_to_client_atomic(a_item.client_sockfd, std::format("{}{} seconds.", pad("connected for:", 20), ss::doubletime::now_as_double() - double(l_conn_time)));
			unlock_client_output(a_item.client_sockfd);
		} else {
			send_to_client(a_item.client_sockfd, "not logged in");
		}
		return false;
	}
	if (l_cmdv[0] == "HELP") {
		// display help file
		ss::data l_help;
		l_help.load_file("help.txt");
		std::string l_string = l_help.read_std_str(l_help.size());
		send_to_client(a_item.client_sockfd, l_string);
		return false;
	}
	if (l_cmdv[0] == "USERS") {
		// display user list
		lock_client_output(a_item.client_sockfd);
		send_to_client_atomic(a_item.client_sockfd, "username        priv online last seen");
		m_user_records_mtx.lock();
		for (auto& [key, value] : m_user_records) {
			send_to_client_atomic(a_item.client_sockfd, std::format("{}{}{}{}", pad(key, 16), pad(std::format("{}", value.priv_level), 5), pad(std::format("{}", value.logged_in), 7), value.last.iso8601_ms()));
		}
		send_to_client_atomic(a_item.client_sockfd, std::format("{} user records.", m_user_records.size()));
		m_user_records_mtx.unlock();
		unlock_client_output(a_item.client_sockfd);
		return false;
	}
	if (l_cmdv[0] == "BROADCAST") {
		// if auth_policy >= 2 check if user is -1 or less
		auto l_priv_level = priv_level(l_user);
		if ((m_auth_policy >= 2) && (l_priv_level.value() > -1)) {
			send_to_client(a_item.client_sockfd, std::format("[command_server: you do not have privileges to execute the command {}.", l_cmdv[0]));
			return false;
		}
		std::set<int> l_clients;
		// grab list of connected clients
		m_client_list_mtx.lock();
		for (auto& [key, value] : m_client_list)
			l_clients.insert(key);
		m_client_list_mtx.unlock();
		// now remove ourselves
		l_clients.erase(a_item.client_sockfd);
		// iterate the set and send out the broadcast
		for (auto& i : l_clients) {
			lock_client_output(i);
			send_to_client_atomic(i, std::format("[broadcast message from user: {}]", l_user));
			send_to_client_atomic(i, l_cmdv[1]);
			unlock_client_output(i);
		}
		send_to_client(a_item.client_sockfd, std::format("[command_server: sent BROADCAST message to {} users.", l_clients.size()));
		return false;
	}
	if (l_cmdv[0] == "DOWN") {
		// if auth_policy >= 2 check if user is -2 or less
		auto l_priv_level = priv_level(l_user);
		if ((m_auth_policy >= 2) && (l_priv_level.value() > -2)) {
			send_to_client(a_item.client_sockfd, std::format("[command_server: you do not have privileges to execute the command {}.", l_cmdv[0]));
			return false;
		}
		send_to_client(a_item.client_sockfd, "[command_server: requesting server DOWN]");
		m_request_down = true;
		return true;
	}
	
	std::string l_response = std::format("[command_server: internal command {} not recognized]", l_cmdv[0]);
	send_to_client(a_item.client_sockfd, l_response);
	return false;
}

} // namespace net
} // namespace ss
