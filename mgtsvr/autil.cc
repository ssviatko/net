#include <iostream>
#include <string>
#include <optional>
#include <format>

#include <getopt.h>

#include "auth.h"
#include "log.h"

std::string g_color_highlight = ss::color_gs(ss::color_gs_name("AQUAMARINE"));
std::string g_color_heading = ss::color_gs(ss::color_gs_name("DARKGREEN"));
std::string g_color_error = ss::color_gs(ss::color_gs_name("PINK"));
std::string g_color_default = ss::COLOR_DEFAULT;

class util_auth : public ss::net::auth {
public:
	util_auth(ss::net::auth::role a_role) : auth(a_role) { };
	virtual ~util_auth() { }
	void cmd_list(std::string& a_authdb);
	void cmd_create(std::string& a_authdb);
	void cmd_loginout(std::string& a_authdb, std::string& a_username);
	void cmd_adduser(std::string a_authdb, std::string a_username, std::string a_passphrase, int a_privilege);
	void cmd_deluser(std::string a_authdb, std::string a_username);
	void cmd_setpriv(std::string a_authdb, std::string a_username, int a_privilege);
	void cmd_setpp(std::string a_authdb, std::string a_username, std::string a_passphrase);
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
		std::cout << g_color_highlight << "list:" << g_color_error << " unable to open auth DB: " << a_authdb << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	}
	std::cout << g_color_heading << "username        priv last seen                        creation date" << g_color_default << std::endl;
	for (auto& [key, value] : m_user_records) {
		std::cout << std::format("{}{}{}{}", pad(key, 16), pad(std::format("{}", value.priv_level), 5), (double(value.last) == 0.0) ? "never                            " : pad(value.last.iso8601_ms(), 33), value.creation.iso8601_ms()) << std::endl;
	}
	std::cout << g_color_highlight << std::format("{} user records.", m_user_records.size()) << g_color_default << std::endl;
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
		std::cout << g_color_highlight << "create:" << g_color_error << " auth DB file " << a_authdb << " already exists." << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	}
	bool l_save = save_authdb(a_authdb);
	if (!l_save) {
		std::cout << g_color_highlight << "create:" << g_color_error << " unable to save auth DB: " << a_authdb << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	} else {
		std::cout << g_color_highlight << "create:" << g_color_default << " wrote auth DB: " << g_color_heading << a_authdb << g_color_default << std::endl;
	}
}

void util_auth::cmd_loginout(std::string& a_authdb, std::string& a_username)
{
	bool l_load = load_authdb(a_authdb);
	if (!l_load) {
		std::cout << g_color_highlight << "loginout:" << g_color_error << " unable to open auth DB: " << a_authdb << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	}
	bool l_authenticated = force_authenticate(a_username);
	if (!l_authenticated) {
		std::cout << g_color_highlight << "loginout:" << g_color_error << " unable to log in user: " << a_username << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	}
	bool l_logged_out = logout(a_username);
	if (!l_logged_out) {
		std::cout << g_color_highlight << "loginout:" << g_color_error << " unable to log out user: " << a_username << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	}
	bool l_save = save_authdb(a_authdb);
	if (!l_save) {
		std::cout << g_color_highlight << "loginout:" << g_color_error << " unable to save auth DB: " << a_authdb << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	} else {
		std::cout << g_color_highlight << "loginout:" << g_color_default << " success, wrote auth DB: " << g_color_heading << a_authdb << g_color_default << std::endl;
	}
}

void util_auth::cmd_adduser(std::string a_authdb, std::string a_username, std::string a_passphrase, int a_privilege)
{
	bool l_load = load_authdb(a_authdb);
	if (!l_load) {
		std::cout << g_color_highlight << "adduser:" << g_color_error << " unable to open auth DB: " << a_authdb << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	}
	bool l_added = add_user_plaintext_pw(a_username, a_passphrase);
	if (!l_added) {
		std::cout << g_color_highlight << "adduser:" << g_color_error << " unable to add user: " << g_color_heading << a_username << g_color_error << " (perhaps it already exists)" << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	}
	bool l_setpriv = set_priv_level(a_username, a_privilege);
	if (!l_setpriv) {
		std::cout << g_color_highlight << "adduser:" << g_color_error << " unable to set privileges for user: " << a_username << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	}
	bool l_save = save_authdb(a_authdb);
	if (!l_save) {
		std::cout << g_color_highlight << "adduser:" << g_color_error << " unable to save auth DB: " << a_authdb << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	} else {
		std::cout << g_color_highlight << "adduser:" << g_color_default << " success, wrote auth DB: " << g_color_heading << a_authdb << g_color_default << std::endl;
	}	
}

void util_auth::cmd_deluser(std::string a_authdb, std::string a_username)
{
	bool l_load = load_authdb(a_authdb);
	if (!l_load) {
		std::cout << g_color_highlight << "deluser:" << g_color_error << " unable to open auth DB: " << a_authdb << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	}
	bool l_del = delete_user(a_username);
	if (!l_del) {
		std::cout << g_color_highlight << "deluser:" << g_color_error << " unable to delete user: " << g_color_heading << a_username << g_color_error << " (user does not exist)" << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	}
	bool l_save = save_authdb(a_authdb);
	if (!l_save) {
		std::cout << g_color_highlight << "deluser:" << g_color_error << " unable to save auth DB: " << a_authdb << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	} else {
		std::cout << g_color_highlight << "deluser:" << g_color_default << " success, wrote auth DB: " << g_color_heading << a_authdb << g_color_default << std::endl;
	}	
}

void util_auth::cmd_setpriv(std::string a_authdb, std::string a_username, int a_privilege)
{
	bool l_load = load_authdb(a_authdb);
	if (!l_load) {
		std::cout << g_color_highlight << "setpriv:" << g_color_error << " unable to open auth DB: " << a_authdb << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	}
	bool l_set = set_priv_level(a_username, a_privilege);
	if (!l_set) {
		std::cout << g_color_highlight << "setpriv:" << g_color_error << " unable to set privileges for user: " << g_color_heading << a_username << g_color_error << " (user does not exist)" << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	}
	bool l_save = save_authdb(a_authdb);
	if (!l_save) {
		std::cout << g_color_highlight << "setpriv:" << g_color_error << " unable to save auth DB: " << a_authdb << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	} else {
		std::cout << g_color_highlight << "setpriv:" << g_color_default << " success, wrote auth DB: " << g_color_heading << a_authdb << g_color_default << std::endl;
	}	
}

void util_auth::cmd_setpp(std::string a_authdb, std::string a_username, std::string a_passphrase)
{
	bool l_load = load_authdb(a_authdb);
	if (!l_load) {
		std::cout << g_color_highlight << "setpp:" << g_color_error << " unable to open auth DB: " << a_authdb << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	}
	bool l_set = force_change_pw_plaintext_pw(a_username, a_passphrase);
	if (!l_set) {
		std::cout << g_color_highlight << "setpp:" << g_color_error << " unable to set passphrase for user: " << g_color_heading << a_username << g_color_error << " (user does not exist)" << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	}
	bool l_save = save_authdb(a_authdb);
	if (!l_save) {
		std::cout << g_color_highlight << "setpp:" << g_color_error << " unable to save auth DB: " << a_authdb << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	} else {
		std::cout << g_color_highlight << "setpp:" << g_color_default << " success, wrote auth DB: " << g_color_heading << a_authdb << g_color_default << std::endl;
	}	
}

void kill_color()
{
	g_color_highlight = "";
	g_color_default = "";
	g_color_heading = "";
	g_color_error = "";
}

struct option g_options[] = {
	{ "list", required_argument, NULL, 'l' },
	{ "create", required_argument, NULL, 'c' },
	{ "user", required_argument, NULL, 'u' },
	{ "loginout", required_argument, NULL, 'o' },
	{ "nocolor", no_argument, NULL, 1000 },
	{ "adduser", required_argument, NULL, 'a' },
	{ "passphrase", required_argument, NULL, 'p' },
	{ "privilege", required_argument, NULL, 'v' },
	{ "deluser", required_argument, NULL, 'd' },
	{ "setpriv", required_argument, NULL, 1001 },
	{ "setpp", required_argument, NULL, 1002 },
	{ NULL, 0, NULL, 0 }
};

int main(int argc, char **argv)
{
	if (argc == 1) {
		std::cout << g_color_highlight << "usage:" << g_color_default << " autil " << g_color_heading << "(options)" << g_color_default << " <authdb>" << std::endl;
		std::cout << g_color_heading << "  -u (--user) <username>" << g_color_default << " Specify user name" << std::endl;
		std::cout << g_color_heading << "  -p (--passphrase) <phrase>" << g_color_default << " Specify passphrase" << std::endl;
		std::cout << g_color_heading << "  -v (--privilege) <privilege>" << g_color_default << " Specify privilege level" << std::endl;
		std::cout << g_color_heading << "  -c (--create) <auth_db>" << g_color_default << " Create new auth DB with default users" << std::endl;
		std::cout << g_color_heading << "  -l (--list) <auth_db>" << g_color_default << " Show user info in auth DB" << std::endl;
		std::cout << g_color_heading << "  -o (--loginout) <auth_db>" << g_color_default << " Log user specified by " << g_color_heading << "-u" << g_color_default << " in and out" << std::endl;
		std::cout << g_color_heading << "  -a (--adduser) <auth_db>" << g_color_default << " Add new user specified by " << g_color_heading << "-u" << g_color_default;
			std::cout << " with passphrase specified by " << g_color_heading << "-p" << g_color_default << " and optional privilege level " << g_color_heading << "-v" << g_color_default;
			std::cout << " (default 0)" << std::endl;
		std::cout << g_color_heading << "  -d (--deluser) <auth_db>" << g_color_default << " delete user specified by " << g_color_heading << "-u" << std::endl;
		std::cout << g_color_heading << "     (--setpriv) <auth_db>" << g_color_default << " set privileges for user specified by " << g_color_heading << "-u" << g_color_default;
			std::cout << " and mandatory privilege level " << g_color_heading << "-v" << g_color_default << std::endl;
		std::cout << g_color_heading << "     (--setpp) <auth_db>" << g_color_default << " set passphrase for user specified by " << g_color_heading << "-u" << g_color_default;
			std::cout << " and passphrase " << g_color_heading << "-p" << g_color_default << std::endl;
		std::cout << g_color_heading << "     (--nocolor)" << g_color_default << " kill colors" << std::endl;
		std::cout << "  options must be specified in order, e.g. -u, -p, -v must preceed any option that expects a username, passphrase, etc" << std::endl;
		std::cout << g_color_highlight << "examples:" << g_color_default << std::endl;
		std::cout << g_color_heading << "  autil -c mydb" << g_color_default << " create new DB named mydb" << std::endl;
		std::cout << g_color_heading << "  autil -l mydb" << g_color_default << " list contents of DB named mydb" << std::endl;
		std::cout << g_color_heading << "  autil --nocolor -l mydb" << g_color_default << " list contents of DB named mydb with no colors (for use with awk and other tools)" << std::endl;
		std::cout << g_color_heading << "  autil -u nobody -o mydb" << g_color_default << " login/out user nobody on mydb" << std::endl;
		std::cout << g_color_heading << "  autil -u nobody -p \"foo foo\" -v 2 -a mydb" << g_color_default << " add user nobody with passphrase \"foo foo\" and privilege level 2 to mydb" << std::endl;
		std::cout << g_color_heading << "  autil -u nobody -p \"foo foo\" -a mydb" << g_color_default << " add user nobody with passphrase \"foo foo\" and default privilege level (0) to mydb" << std::endl;
		std::cout << g_color_heading << "  autil -u nobody -d mydb" << g_color_default << " delete user nobody on mydb" << std::endl;
		std::cout << g_color_heading << "  autil -u nobody -v -2 --setpriv mydb" << g_color_default << " set nobody's privileges to -2 (superuser) on mydb" << std::endl;
		std::cout << g_color_heading << "  autil -u nobody -p \"foo foo\" --setpp mydb" << g_color_default << " set nobody's passphrase to \"foo foo\" on mydb" << std::endl;
		exit(EXIT_FAILURE);
	}
	
	std::string l_authdbname;
	util_auth l_auth_cli(ss::net::auth::CLIENT);
	util_auth l_auth_svr(ss::net::auth::SERVER);
	std::string l_username;
	bool l_username_specified = false;
	std::string l_passphrase;
	bool l_passphrase_specified = false;
	int l_privilege = 0;
	bool l_privilege_specified = false;
	
	int opt;
	while ((opt = getopt_long(argc, argv, "u:c:l:o:a:p:v:d:", g_options, NULL)) != -1) {
		switch (opt) {
		case 1000:
		{
			kill_color();
		}
			break;
		case 'u':
		{
			l_username = std::string(optarg);
			l_username_specified = true;
		}
			break;
		case 'p':
		{
			l_passphrase = std::string(optarg);
			l_passphrase_specified = true;
		}
			break;
		case 'v':
		{
			l_privilege = atoi(optarg);
			l_privilege_specified = true;
		}
			break;
		case 1001:
		{
			l_authdbname = std::string(optarg);
			if (!l_username_specified) {
				std::cout << g_color_highlight << "setpriv:" << g_color_error << " must specify a user name to change privileges." << g_color_default << std::endl;
				exit(EXIT_FAILURE);				
			}
			if (!l_privilege_specified) {
				std::cout << g_color_highlight << "setpriv:" << g_color_error << " must specify new privilege level for this user." << g_color_default << std::endl;
				exit(EXIT_FAILURE);				
			}
			std::cout << g_color_highlight << "setpriv:" << g_color_default << " attempting to set privilege level " << g_color_heading << l_privilege << g_color_default;
			std::cout << " for user " << g_color_heading << l_username << g_color_default;
			std::cout << " on auth DB: " << g_color_heading << l_authdbname << g_color_default << "..." << std::endl;
			l_auth_svr.cmd_setpriv(l_authdbname, l_username, l_privilege);
		}
			break;
		case 1002:
		{
			l_authdbname = std::string(optarg);
			if (!l_username_specified) {
				std::cout << g_color_highlight << "setpp:" << g_color_error << " must specify a user name to change passphrase." << g_color_default << std::endl;
				exit(EXIT_FAILURE);				
			}
			if (!l_passphrase_specified) {
				std::cout << g_color_highlight << "setpp:" << g_color_error << " must specify new passphrase for this user." << g_color_default << std::endl;
				exit(EXIT_FAILURE);				
			}
			std::cout << g_color_highlight << "setpp:" << g_color_default << " attempting to change passphrase for user " << g_color_heading << l_username << g_color_default;
			std::cout << " on auth DB: " << g_color_heading << l_authdbname << g_color_default << "..." << std::endl;
			l_auth_svr.cmd_setpp(l_authdbname, l_username, l_passphrase);
		}
			break;
		case 'c':
		{
			l_authdbname = std::string(optarg);
			std::cout << "attempting to create new auth DB: " << g_color_heading << l_authdbname << g_color_default << "..." << std::endl;
			l_auth_svr.cmd_create(l_authdbname);
		}
			break;
		case 'a':
		{
			l_authdbname = std::string(optarg);
			if (!l_username_specified) {
				std::cout << g_color_highlight << "adduser:" << g_color_error << " must specify a user name to add." << g_color_default << std::endl;
				exit(EXIT_FAILURE);				
			}
			if (!l_passphrase_specified) {
				std::cout << g_color_highlight << "adduser:" << g_color_error << " must specify a pass phrase for this user." << g_color_default << std::endl;
				exit(EXIT_FAILURE);				
			}
			std::cout << g_color_highlight << "adduser:" << g_color_default << " attempting to add user " << g_color_heading << l_username << g_color_default;
			std::cout << " with privilege level " << g_color_heading << l_privilege << g_color_default;
			std::cout << " on auth DB: " << g_color_heading << l_authdbname << g_color_default << "..." << std::endl;
			l_auth_svr.cmd_adduser(l_authdbname, l_username, l_passphrase, l_privilege);
		}
			break;
		case 'd':
		{
			l_authdbname = std::string(optarg);
			if (!l_username_specified) {
				std::cout << g_color_highlight << "deluser:" << g_color_error << " must specify a user name to delete." << g_color_default << std::endl;
				exit(EXIT_FAILURE);				
			}
			std::cout << g_color_highlight << "deluser:" << g_color_default << " attempting to delete user " << g_color_heading << l_username << g_color_default << std::endl;
			l_auth_svr.cmd_deluser(l_authdbname, l_username);
		}
			break;
		case 'l':
		{
			l_authdbname = std::string(optarg);
			std::cout << "attempting to list auth DB: " << g_color_heading << l_authdbname << g_color_default << "..." << std::endl;
			l_auth_svr.cmd_list(l_authdbname);
		}
			break;
		case 'o':
		{
			if (!l_username_specified) {
				std::cout << g_color_highlight << "loginout:" << g_color_error << " must specify a user name to log in and out." << g_color_default << std::endl;
				exit(EXIT_FAILURE);
			}
			l_authdbname = std::string(optarg);
			std::cout << g_color_highlight << "loginout:" << g_color_default << " attempting to log user " << g_color_heading << l_username << g_color_default << " in and out on auth DB: " << g_color_heading << l_authdbname << g_color_default << "..." << std::endl;
			l_auth_svr.cmd_loginout(l_authdbname, l_username);
		}
		}
	}
	return 0;
}
