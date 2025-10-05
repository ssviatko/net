#include <iostream>
#include <string>
#include <optional>
#include <format>

#include <getopt.h>

#include "auth.h"

struct option g_options[] = {
	{ "list", required_argument, NULL, 'l' },
	{ "create", required_argument, NULL, 'c' },
	{ NULL, 0, NULL, 0 }
};

class util_auth : public ss::net::auth {
public:
	util_auth(ss::net::auth::role a_role) : auth(a_role) { };
	virtual ~util_auth() { }
	void cmd_list(std::string& a_authdb);
	void cmd_create(std::string& a_authdb);
	std::string pad(const std::string& a_string, std::size_t a_len);
};

std::string util_auth::pad(const std::string& a_string, std::size_t a_len)
{
	std::string l_ret;
	for (std::size_t i = 0; i < a_len; ++i)
		l_ret += ' ';
	l_ret = a_string + l_ret;
	return l_ret.substr(0, a_len);
}

void util_auth::cmd_list(std::string& a_authdb)
{
	bool l_load = load_authdb(a_authdb);
	if (!l_load) {
		std::cout << "list: unable to open auth DB: " << a_authdb << std::endl;
		exit(EXIT_FAILURE);
	}
	std::cout << "username        priv last seen                        creation date" << std::endl;
	for (auto& [key, value] : m_user_records) {
		std::cout << std::format("{}{}{}{}", pad(key, 16), pad(std::format("{}", value.priv_level), 5), pad(value.last.iso8601_ms(), 33), value.creation.iso8601_ms()) << std::endl;
	}
	std::cout << std::format("{} user records.", m_user_records.size()) << std::endl;
}

void util_auth::cmd_create(std::string& a_authdb)
{
	bool l_load = load_authdb(a_authdb);
	if (!l_load) {
		// if we didn't load the auth db (i.e. we're starting from scratch), create some default accounts
		bool l_add_user_success;
		l_add_user_success = add_user_plaintext_pw("user", "user");
		std::cout << std::format("add default user user: {}", l_add_user_success) << std::endl;
		l_add_user_success = add_user_plaintext_pw("admin", "admin");
		set_priv_level("admin", -1);
		std::cout << std::format("add default user admin: {}", l_add_user_success) << std::endl;
		l_add_user_success = add_user_plaintext_pw("operator", "operator");
		set_priv_level("operator", -2);
		std::cout << std::format("add default user operator: {}", l_add_user_success) << std::endl;
		l_add_user_success = add_user_plaintext_pw("chump", "chump");
		set_priv_level("chump", 1);
		std::cout << std::format("add default user chump: {}", l_add_user_success) << std::endl;
	} else {
		std::cout << "create: auth DB file " << a_authdb << " already exists." << std::endl;
		exit(EXIT_FAILURE);
	}
	bool l_save = save_authdb(a_authdb);
	if (!l_save) {
		std::cout << "create: unable to save auth DB: " << a_authdb << std::endl;
		exit(EXIT_FAILURE);
	} else {
		std::cout << "create: wrote auth DB: " << a_authdb << std::endl;
	}
}

int main(int argc, char **argv)
{
	if (argc == 1) {
		std::cout << "usage: autil (options) <authdb>" << std::endl;
		std::cout << "  -c (--create) <auth_db> Create new auth DB with default user" << std::endl;
		std::cout << "  -l (--list) <auth_db> Show user info in auth DB" << std::endl;
		exit(EXIT_FAILURE);
	}
	
	std::string l_authdbname;
	util_auth l_auth_cli(ss::net::auth::CLIENT);
	util_auth l_auth_svr(ss::net::auth::SERVER);
	
	int opt;
	while ((opt = getopt_long(argc, argv, "c:l:", g_options, NULL)) != -1) {
		switch (opt) {
		case 'c':
		{
			l_authdbname = std::string(optarg);
			std::cout << "attempting to create new auth DB: " << l_authdbname << "..." << std::endl;
			l_auth_svr.cmd_create(l_authdbname);
		}
			break;
		case 'l':
		{
			l_authdbname = std::string(optarg);
			std::cout << "attempting to list auth DB: " << l_authdbname << "..." << std::endl;
			l_auth_svr.cmd_list(l_authdbname);
		}
			break;
		}
	}
	return 0;
}
