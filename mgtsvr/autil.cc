#include <iostream>
#include <string>
#include <optional>
#include <format>

#include <getopt.h>
#include <termios.h>
#include <unistd.h>

#include "auth.h"
#include "log.h"

//std::string g_color_highlight = ss::color_gs(ss::color_gs_name("AQUAMARINE"));
//std::string g_color_heading = ss::color_gs(ss::color_gs_name("DARKGREEN"));
//std::string g_color_error = ss::color_gs(ss::color_gs_name("PINK"));
std::string g_color_highlight = ss::COLOR_LIGHTGREEN;
std::string g_color_heading = ss::COLOR_GREEN;
std::string g_color_error = ss::COLOR_LIGHTRED;
std::string g_color_default = ss::COLOR_DEFAULT;

class util_auth : public ss::net::auth {
public:
	util_auth(ss::net::auth::role a_role) : auth(a_role) { };
	virtual ~util_auth() { }
	void cmd_list(std::string& a_authdb, bool a_listph);
	void cmd_create(std::string& a_authdb);
	void cmd_loginout(std::string& a_authdb, std::string& a_username);
	void cmd_adduser(std::string a_authdb, std::string a_username, std::string a_passphrase, int a_privilege);
	void cmd_adduserhash(std::string a_authdb, std::string a_username, std::string a_passphrasehash, int a_privilege);
	void cmd_deluser(std::string a_authdb, std::string a_username);
	void cmd_setpriv(std::string a_authdb, std::string a_username, int a_privilege);
	void cmd_setpp(std::string a_authdb, std::string a_username, std::string a_passphrase);
	void cmd_setph(std::string a_authdb, std::string a_username, std::string a_passphrasehash);
	void cmd_changem(std::string a_authdb, std::string a_old_passphrase, std::string a_new_passphrase);
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

void util_auth::cmd_list(std::string& a_authdb, bool a_listph)
{
	bool l_load = load_authdb(a_authdb);
	if (!l_load) {
		std::cout << g_color_highlight << "list:" << g_color_error << " unable to open auth DB: " << a_authdb << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	}
	std::cout << g_color_heading << "username        priv last seen                        creation date                    ";
	if (a_listph) {
		std::cout << "passphrase hash";
	}
	std::cout << g_color_default << std::endl;
	for (auto& [key, value] : m_user_records) {
		std::cout << std::format("{}{}{}{}", pad(key, 16), pad(std::format("{}", value.priv_level), 5), (double(value.last) == 0.0) ? "never                            " : pad(value.last.iso8601_ms(), 33), pad(value.creation.iso8601_ms(), 33));
		if (a_listph) {
			std::cout << value.password_hash;
		}
		std::cout << std::endl;
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
		std::cout << g_color_highlight << "create:" << g_color_default << std::format(" add default user user: {}", l_add_user_success) << std::endl;
		l_add_user_success = add_user_plaintext_pw("admin", "admin");
		set_priv_level("admin", -1);
		std::cout << g_color_highlight << "create:" << g_color_default << std::format(" add default user admin: {}", l_add_user_success) << std::endl;
		l_add_user_success = add_user_plaintext_pw("operator", "operator");
		set_priv_level("operator", -2);
		std::cout << g_color_highlight << "create:" << g_color_default << std::format(" add default user operator: {}", l_add_user_success) << std::endl;
		l_add_user_success = add_user_plaintext_pw("chump", "chump");
		set_priv_level("chump", 1);
		std::cout << g_color_highlight << "create:" << g_color_default << std::format(" add default user chump: {}", l_add_user_success) << std::endl;
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

void util_auth::cmd_adduserhash(std::string a_authdb, std::string a_username, std::string a_passphrasehash, int a_privilege)
{
	bool l_load = load_authdb(a_authdb);
	if (!l_load) {
		std::cout << g_color_highlight << "adduserhash:" << g_color_error << " unable to open auth DB: " << a_authdb << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	}
	bool l_added = add_user(a_username, a_passphrasehash);
	if (!l_added) {
		std::cout << g_color_highlight << "adduserhash:" << g_color_error << " unable to add user: " << g_color_heading << a_username << g_color_error << " (perhaps it already exists)" << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	}
	bool l_setpriv = set_priv_level(a_username, a_privilege);
	if (!l_setpriv) {
		std::cout << g_color_highlight << "adduserhash:" << g_color_error << " unable to set privileges for user: " << a_username << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	}
	bool l_save = save_authdb(a_authdb);
	if (!l_save) {
		std::cout << g_color_highlight << "adduserhash:" << g_color_error << " unable to save auth DB: " << a_authdb << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	} else {
		std::cout << g_color_highlight << "adduserhash:" << g_color_default << " success, wrote auth DB: " << g_color_heading << a_authdb << g_color_default << std::endl;
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

void util_auth::cmd_setph(std::string a_authdb, std::string a_username, std::string a_passphrasehash)
{
	bool l_load = load_authdb(a_authdb);
	if (!l_load) {
		std::cout << g_color_highlight << "setph:" << g_color_error << " unable to open auth DB: " << a_authdb << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	}
	bool l_set = force_change_pw(a_username, a_passphrasehash);
	if (!l_set) {
		std::cout << g_color_highlight << "setph:" << g_color_error << " unable to set passphrase hash for user: " << g_color_heading << a_username << g_color_error << " (user does not exist)" << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	}
	bool l_save = save_authdb(a_authdb);
	if (!l_save) {
		std::cout << g_color_highlight << "setph:" << g_color_error << " unable to save auth DB: " << a_authdb << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	} else {
		std::cout << g_color_highlight << "setph:" << g_color_default << " success, wrote auth DB: " << g_color_heading << a_authdb << g_color_default << std::endl;
	}	
}

void util_auth::cmd_changem(std::string a_authdb, std::string a_old_passphrase, std::string a_new_passphrase)
{
	bool l_load = load_authdb(a_authdb);
	if (!l_load) {
		std::cout << g_color_highlight << "change master passphrase:" << g_color_error << " unable to open auth DB: " << a_authdb << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	}
	set_master_passphrase(a_new_passphrase);
	bool l_save = save_authdb(a_authdb);
	if (!l_save) {
		std::cout << g_color_highlight << "change master passphrase:" << g_color_error << " unable to save auth DB: " << a_authdb << g_color_default << std::endl;
		exit(EXIT_FAILURE);
	} else {
		std::cout << g_color_highlight << "change master passphrase:" << g_color_default << " success, wrote auth DB: " << g_color_heading << a_authdb << g_color_default << std::endl;
	}
}

void kill_color()
{
	g_color_highlight = "";
	g_color_default = "";
	g_color_heading = "";
	g_color_error = "";
}

enum {
	OPT_NOCOLOR = 1000,
	OPT_SETPRIV,
	OPT_SETPP,
	OPT_SETPH,
	OPT_ADDUSERHASH,
	OPT_LISTPH,
	OPT_CPACKGEN,
	OPT_CRGEN,
	OPT_CRGENHASH,
	OPT_PHGEN,
	OPT_ASKM,
	OPT_SHOWM,
	OPT_CHANGEM
};

struct option g_options[] = {
	{ "help", optional_argument, NULL, '?' },
	{ "list", required_argument, NULL, 'l' },
	{ "create", required_argument, NULL, 'c' },
	{ "user", required_argument, NULL, 'u' },
	{ "loginout", required_argument, NULL, 'o' },
	{ "nocolor", no_argument, NULL, OPT_NOCOLOR },
	{ "adduser", required_argument, NULL, 'a' },
	{ "adduserhash", required_argument, NULL, OPT_ADDUSERHASH },
	{ "passphrase", required_argument, NULL, 'p' },
	{ "passphrasehash", required_argument, NULL, 'h' },
	{ "privilege", required_argument, NULL, 'v' },
	{ "deluser", required_argument, NULL, 'd' },
	{ "setpriv", required_argument, NULL, OPT_SETPRIV },
	{ "setpp", required_argument, NULL, OPT_SETPP },
	{ "setph", required_argument, NULL, OPT_SETPH },
	{ "listph", no_argument, NULL, OPT_LISTPH },
	{ "cpackgen", required_argument, NULL, OPT_CPACKGEN },
	{ "crgen", no_argument, NULL, OPT_CRGEN },
	{ "crgenhash", no_argument, NULL, OPT_CRGENHASH },
	{ "session", required_argument, NULL, 's' },
	{ "phgen", no_argument, NULL, OPT_PHGEN },
	{ "master", required_argument, NULL, 'm' },
	{ "askm", no_argument, NULL, OPT_ASKM },
	{ "showm", no_argument, NULL, OPT_SHOWM },
	{ "changem", required_argument, NULL, OPT_CHANGEM },
	{ NULL, 0, NULL, 0 }
};

void usage_heading()
{
	std::cout << g_color_highlight << "autil" << g_color_heading << " - Authorization Utility for managing JSON ss::net::auth databases" << g_color_default << std::endl;
	std::cout << g_color_heading << "Release number " << g_color_default << RELEASE_NUMBER << g_color_heading << " Build number " << g_color_default << BUILD_NUMBER << g_color_heading << " Built on " << g_color_default << BUILD_DATE << std::endl;
}

void usage()
{
	usage_heading();
	std::cout << g_color_highlight << "usage:" << g_color_default << " autil " << g_color_heading << "(options)" << g_color_default << std::endl;
	std::cout << g_color_heading << "  -u (--user) <username>" << g_color_default << " Specify user name" << std::endl;
	std::cout << g_color_heading << "  -p (--passphrase) <phrase>" << g_color_default << " Specify passphrase" << std::endl;
	std::cout << g_color_heading << "  -h (--passphrasehash) <hash>" << g_color_default << " Specify passphrase hash" << std::endl;
	std::cout << g_color_heading << "     (--phgen)" << g_color_default << " generate passphrase hash based on passphrase specified by " << g_color_heading << "-p" << g_color_default << std::endl;
	std::cout << g_color_heading << "  -v (--privilege) <privilege>" << g_color_default << " Specify privilege level (recommended -16 to +15)" << std::endl;
	std::cout << g_color_heading << "  -m (--master) <phrase>" << g_color_default << " Specify master passphrase" << std::endl;
	std::cout << g_color_heading << "     (--askm)" << g_color_default << " ask for master passphrase at command line instead" << std::endl;
	std::cout << g_color_heading << "     (--showm)" << g_color_default << " show master passphrase entered using --askm or -m (debug option)" << std::endl;
	std::cout << g_color_heading << "     (--changem) <auth_db>" << g_color_default << " change master passphrase on DB (interactive)" << std::endl;
	std::cout << g_color_heading << "  -c (--create) <auth_db>" << g_color_default << " Create new auth DB with default users" << std::endl;
	std::cout << g_color_heading << "  -l (--list) <auth_db>" << g_color_default << " Show user info in auth DB" << std::endl;
	std::cout << g_color_heading << "     (--listph)" << g_color_default << " show passphrase hashes in " << g_color_heading << "-l" << g_color_default << " DB listing" << std::endl;
	std::cout << g_color_heading << "  -o (--loginout) <auth_db>" << g_color_default << " Log user specified by " << g_color_heading << "-u" << g_color_default << " in and out" << std::endl;
	std::cout << g_color_heading << "  -a (--adduser) <auth_db>" << g_color_default << " Add new user specified by " << g_color_heading << "-u" << g_color_default;
		std::cout << " with passphrase specified by " << g_color_heading << "-p" << g_color_default << " and optional privilege level " << g_color_heading << "-v" << g_color_default;
		std::cout << " (default 0)" << std::endl;
	std::cout << g_color_heading << "     (--adduserhash) <auth_db>" << g_color_default << " Add new user specified by " << g_color_heading << "-u" << g_color_default;
		std::cout << " with passphrase hash specified by " << g_color_heading << "-h" << g_color_default << " and optional privilege level " << g_color_heading << "-v" << g_color_default;
		std::cout << " (default 0)" << std::endl;
	std::cout << g_color_heading << "  -d (--deluser) <auth_db>" << g_color_default << " delete user specified by " << g_color_heading << "-u" << std::endl;
	std::cout << g_color_heading << "     (--setpriv) <auth_db>" << g_color_default << " set privileges for user specified by " << g_color_heading << "-u" << g_color_default;
		std::cout << " and mandatory privilege level " << g_color_heading << "-v" << g_color_default << std::endl;
	std::cout << g_color_heading << "     (--setpp) <auth_db>" << g_color_default << " set passphrase for user specified by " << g_color_heading << "-u" << g_color_default;
		std::cout << " and passphrase " << g_color_heading << "-p" << g_color_default << std::endl;
	std::cout << g_color_heading << "     (--setph) <auth_db>" << g_color_default << " set passphrase hash for user specified by " << g_color_heading << "-u" << g_color_default;
		std::cout << " and passphrase hash " << g_color_heading << "-h" << g_color_default << std::endl;
	std::cout << g_color_heading << "  -s (--session)" << g_color_default << " specify session hash for challenge reponse" << std::endl;
	std::cout << g_color_heading << "     (--cpackgen) <auth_db>" << g_color_default << " generate challenge pack for user specified by " << g_color_heading << "-u" << g_color_default << " on auth_db" << std::endl;
	std::cout << g_color_heading << "     (--crgen)" << g_color_default << " generate challenge response using session hash " << g_color_heading << "-s" << g_color_default;
		std::cout << " and passphrase specified by " << g_color_heading << "-p" << g_color_default << std::endl;
	std::cout << g_color_heading << "     (--crgenhash)" << g_color_default << " generate challenge response using session hash " << g_color_heading << "-s" << g_color_default;
		std::cout << " and passphrase hash specified by " << g_color_heading << "-h" << g_color_default << std::endl;
	std::cout << g_color_heading << "     (--nocolor)" << g_color_default << " kill colors" << std::endl;
	std::cout << g_color_heading << "  -? (--help) <optional screen>" << g_color_default << " show this help/usage screen, or specify optional screen: " << g_color_heading << "examples" << g_color_default << " (show examples detail)" << std::endl;
	std::cout << g_color_heading << "  options must be specified in order, e.g. -u, -p, -v must preceed any option that expects a username, passphrase, etc" << g_color_default << std::endl;
	std::cout << g_color_heading << "  every command that references an auth DB must also have a master passphrase specified with either -m or --askm to seal/unseal the DB." << g_color_default << std::endl;
	std::cout << g_color_heading << "  all hashes (passphrase hashes, session hashes) must be base64 string 64 characters in length or the program will complain." << g_color_default << std::endl;
	exit(EXIT_FAILURE);
}

void help_examples()
{
	usage_heading();
	std::cout << g_color_highlight << "examples: (all examples with -m or --askm assume use of master passphrase to seal/unseal the DB)" << g_color_default << std::endl;
	std::cout << g_color_heading << "  autil -m \"example\" -c mydb" << g_color_default << " create new DB named mydb" << std::endl;
	std::cout << g_color_heading << "  autil -m \"example\" -l mydb" << g_color_default << " list contents of DB named mydb" << std::endl;
	std::cout << g_color_heading << "  autil -m \"example\" --listph -l mydb" << g_color_default << " list contents of DB named mydb, include passphrase hashes for each account" << std::endl;
	std::cout << g_color_heading << "  autil -m \"example\" --nocolor -l mydb" << g_color_default << " list contents of DB named mydb with no colors (for use with awk and other tools)" << std::endl;
	std::cout << g_color_heading << "  autil -m \"example\" -u nobody -o mydb" << g_color_default << " login/out user nobody on mydb" << std::endl;
	std::cout << g_color_heading << "  autil -m \"example\" -u nobody -p \"foo foo\" -v 2 -a mydb" << g_color_default << " add user nobody with passphrase \"foo foo\" and privilege level 2 to mydb" << std::endl;
	std::cout << g_color_heading << "  autil -m \"example\" -u nobody -p \"foo foo\" -a mydb" << g_color_default << " add user nobody with passphrase \"foo foo\" and default privilege level (0) to mydb" << std::endl;
	std::cout << g_color_heading << "  autil -m \"example\" -u nobody -d mydb" << g_color_default << " delete user nobody on mydb" << std::endl;
	std::cout << g_color_heading << "  autil -m \"example\" -u nobody -v -2 --setpriv mydb" << g_color_default << " set nobody's privileges to -2 (superuser) on mydb" << std::endl;
	std::cout << g_color_heading << "  autil -m \"example\" -u nobody -p \"foo foo\" --setpp mydb" << g_color_default << " set nobody's passphrase to \"foo foo\" on mydb" << std::endl;
	std::cout << g_color_heading << "  autil -p banana --phgen" << g_color_default << " show passphrase hash for passphrase \"banana\"." << std::endl;
	std::cout << g_color_heading << "  autil --askm -l mydb" << g_color_default << " list contents of DB named mydb, ask for master passphrase interactively instead of using -m" << std::endl;
	std::cout << g_color_heading << "  autil --askm --showm -l mydb" << g_color_default << " list contents of DB named mydb, ask for master passphrase interactively but show it on screen after entry (debug option)" << std::endl;
	std::cout << g_color_heading << "  autil --changem mydb" << g_color_default << " change master passphrase for mydb, will ask for old/new passphrases interactively. --showm not applicable" << std::endl;
	exit(EXIT_FAILURE);
}

std::string getpw()
{
	std::string l_password;
	termios oldt;
	tcgetattr(STDIN_FILENO, &oldt);
	termios newt = oldt;
	newt.c_lflag &= ~ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);

	char ch;
	while ((ch = getchar()) != '\n') {
		if (ch == 127) {
			// Handle backspace
			if (!l_password.empty()) {
				l_password.pop_back();
			}
		} else {
			l_password += ch;
		}
	}

	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	std::cout << std::endl;
	return l_password;
}

int main(int argc, char **argv)
{
	if (argc == 1) {
		usage();
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
	bool l_listph = false;
	std::string l_session;
	bool l_session_specified = false;
	std::string l_passphrasehash;
	bool l_passphrasehash_specified = false;
	bool l_master_specified = false;
	
	int opt;
	while ((opt = getopt_long(argc, argv, "u:c:l:o:a:p:v:d:s:h:?::m:", g_options, NULL)) != -1) {
		switch (opt) {
		case '?':
		{
			if (optarg == NULL && optind < argc && argv[optind][0] != '-')
			{
				// correct optarg if user put a space between -? and the option
				optarg = argv[optind++];
			} else if (optarg == NULL) {
				// user did not select an option, just typed -?
				usage();
			}
			// now we can allow a user to type -?option OR -? option (with or without space)
			std::string l_help_option = std::string(optarg);
			if (l_help_option == "examples") {
				help_examples();
			} else {
				// unrecognized help option
				std::cout << g_color_highlight << "help:" << g_color_error << " unrecognized option \"" << l_help_option << "\"." << g_color_default << std::endl;
				usage();
			}
		}
			break;
		case 'm':
		{
			l_auth_svr.set_master_passphrase(std::string(optarg));
			l_master_specified = true;
		}
			break;
		case OPT_ASKM:
		{
			std::cout << "enter master passhrase: ";
			std::string l_firstpw = getpw();
			std::cout << "enter passphrase again: ";
			std::string l_secondpw = getpw();
			if (l_firstpw != l_secondpw) {
				std::cout << g_color_highlight << "ask master passphrase:" << g_color_error << " the two passphrases do not match." << g_color_default << std::endl;
				exit(EXIT_FAILURE);
			}
			l_auth_svr.set_master_passphrase(l_firstpw);
			l_master_specified = true;
		}
			break;
		case OPT_SHOWM:
		{
			if (l_master_specified) {
				std::cout << g_color_highlight << "show master passphrase:" << g_color_default << " the passphrase is: " << g_color_heading << l_auth_svr.get_master_passphrase();
				std::cout << g_color_default << std::endl;
			}
		}
			break;
		case OPT_CHANGEM:
		{
			l_authdbname = std::string(optarg);
			std::cout << "enter old master passhrase: ";
			std::string l_firstoldpw = getpw();
			std::cout << "enter old passphrase again: ";
			std::string l_secondoldpw = getpw();
			if (l_firstoldpw != l_secondoldpw) {
				std::cout << g_color_highlight << "old master passphrase:" << g_color_error << " the two passphrases do not match." << g_color_default << std::endl;
				exit(EXIT_FAILURE);
			}
			std::cout << "enter new master passhrase: ";
			std::string l_firstnewpw = getpw();
			std::cout << "enter new passphrase again: ";
			std::string l_secondnewpw = getpw();
			if (l_firstnewpw != l_secondnewpw) {
				std::cout << g_color_highlight << "new master passphrase:" << g_color_error << " the two passphrases do not match." << g_color_default << std::endl;
				exit(EXIT_FAILURE);
			}
			l_auth_svr.set_master_passphrase(l_firstoldpw);
			l_auth_svr.cmd_changem(l_authdbname, l_firstoldpw, l_firstnewpw);
			// no other activity after executing this command
			exit(EXIT_SUCCESS);
		}
			break;
		case OPT_NOCOLOR:
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
		case 'h':
		{
			l_passphrasehash = std::string(optarg);
			if (l_passphrasehash.size() != 64) {
				std::cout << g_color_error << "passphrase hash size must be 64 characters in length." << g_color_default << std::endl;
				exit(EXIT_FAILURE);
			}
			l_passphrasehash_specified = true;
		}
			break;
		case OPT_PHGEN:
		{
			if (!l_passphrase_specified) {
				std::cout << g_color_highlight << "phgen:" << g_color_error << " must specify a passphrase to generate passphrase hash." << g_color_default << std::endl;
				exit(EXIT_FAILURE);				
			}
			std::string l_ph = l_auth_cli.generate_hash(l_passphrase);
			std::cout << g_color_highlight << "phgen:" << g_color_default << " generating passphrase hash based of provided passphrase." << std::endl;
			std::cout << g_color_highlight << "passphrase hash  : " << g_color_default << l_ph << std::endl;
		}
			break;
		case 'v':
		{
			l_privilege = atoi(optarg);
			l_privilege_specified = true;
		}
			break;
		case 's':
		{
			l_session = std::string(optarg);
			if (l_session.size() != 64) {
				std::cout << g_color_error << "session hash size must be 64 characters in length." << g_color_default << std::endl;
				exit(EXIT_FAILURE);
			}
			l_session_specified = true;
		}
			break;
		case OPT_CPACKGEN:
		{
			l_authdbname = std::string(optarg);
			if (!l_master_specified) {
				std::cout << g_color_highlight << "cpackgen:" << g_color_error << " must specify a master passphrase to seal/unseal auth DB." << g_color_default << std::endl;
				exit(EXIT_FAILURE);
			}
			if (!l_username_specified) {
				std::cout << g_color_highlight << "cpackgen:" << g_color_error << " must specify a user name to generate challenge pack." << g_color_default << std::endl;
				exit(EXIT_FAILURE);				
			}
			bool l_load = l_auth_svr.load_authdb(l_authdbname);
			if (!l_load) {
				std::cout << g_color_highlight << "cpackgen:" << g_color_error << " unable to open auth DB: " << l_authdbname << g_color_default << std::endl;
				exit(EXIT_FAILURE);
			}
			std::optional<ss::net::challenge_pack> l_cpack = l_auth_svr.challenge(l_username);
			if (l_cpack == std::nullopt) {
				std::cout << g_color_highlight << "cpackgen:" << g_color_error << " unable to generate challenge pack" << g_color_default << std::endl;
				exit(EXIT_FAILURE);
			}
			std::cout << g_color_highlight << "cpackgen:" << g_color_default << " generating challenge pack for user " << g_color_heading << l_username << g_color_default;
			std::cout << " on auth DB " << g_color_heading << l_authdbname << g_color_default << std::endl;
			std::cout << g_color_highlight << "session hash     : " << g_color_default << l_cpack->session << std::endl;
			std::cout << g_color_highlight << "expected response: " << g_color_default << l_cpack->expected_response << std::endl;
		}
			break;
		case OPT_CRGEN:
		{
			if (!l_session_specified) {
				std::cout << g_color_highlight << "crgen:" << g_color_error << " must specify a session hash to generate challenge response." << g_color_default << std::endl;
				exit(EXIT_FAILURE);				
			}
			if (!l_passphrase_specified) {
				std::cout << g_color_highlight << "crgen:" << g_color_error << " must specify a passphrase to generate challenge response." << g_color_default << std::endl;
				exit(EXIT_FAILURE);				
			}
			std::optional<std::string> l_cr = l_auth_cli.challenge_response(l_session, l_passphrase);
			if (!l_cr.has_value()) {
				std::cout << g_color_highlight << "crgen:" << g_color_error << " unable to generate challenge response." << g_color_default << std::endl;
				exit(EXIT_FAILURE);
			}
			std::cout << g_color_highlight << "crgen:" << g_color_default << " generating challenge response based of provided session hash and passphrase." << std::endl;
			std::cout << g_color_highlight << "response         : " << g_color_default << l_cr.value() << std::endl;
		}
			break;
		case OPT_CRGENHASH:
		{
			if (!l_session_specified) {
				std::cout << g_color_highlight << "crgenhash:" << g_color_error << " must specify a session hash to generate challenge response." << g_color_default << std::endl;
				exit(EXIT_FAILURE);				
			}
			if (!l_passphrasehash_specified) {
				std::cout << g_color_highlight << "crgenhash:" << g_color_error << " must specify a passphrase hash to generate challenge response." << g_color_default << std::endl;
				exit(EXIT_FAILURE);				
			}
			std::optional<std::string> l_cr = l_auth_cli.challenge_response_with_hash(l_session, l_passphrasehash);
			if (!l_cr.has_value()) {
				std::cout << g_color_highlight << "crgenhash:" << g_color_error << " unable to generate challenge response." << g_color_default << std::endl;
				exit(EXIT_FAILURE);
			}
			std::cout << g_color_highlight << "crgenhash:" << g_color_default << " generating challenge response based of provided session hash and passphrase hash." << std::endl;
			std::cout << g_color_highlight << "response         : " << g_color_default << l_cr.value() << std::endl;
		}
			break;
		case OPT_SETPRIV:
		{
			l_authdbname = std::string(optarg);
			if (!l_master_specified) {
				std::cout << g_color_highlight << "setpriv:" << g_color_error << " must specify a master passphrase to seal/unseal auth DB." << g_color_default << std::endl;
				exit(EXIT_FAILURE);
			}
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
		case OPT_SETPP:
		{
			l_authdbname = std::string(optarg);
			if (!l_master_specified) {
				std::cout << g_color_highlight << "setpp:" << g_color_error << " must specify a master passphrase to seal/unseal auth DB." << g_color_default << std::endl;
				exit(EXIT_FAILURE);
			}
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
		case OPT_SETPH:
		{
			l_authdbname = std::string(optarg);
			if (!l_master_specified) {
				std::cout << g_color_highlight << "setph:" << g_color_error << " must specify a master passphrase to seal/unseal auth DB." << g_color_default << std::endl;
				exit(EXIT_FAILURE);
			}
			if (!l_username_specified) {
				std::cout << g_color_highlight << "setph:" << g_color_error << " must specify a user name to change passphrase hash." << g_color_default << std::endl;
				exit(EXIT_FAILURE);				
			}
			if (!l_passphrasehash_specified) {
				std::cout << g_color_highlight << "setph:" << g_color_error << " must specify new passphrase hash for this user." << g_color_default << std::endl;
				exit(EXIT_FAILURE);				
			}
			std::cout << g_color_highlight << "setph:" << g_color_default << " attempting to change passphrase hash for user " << g_color_heading << l_username << g_color_default;
			std::cout << " on auth DB: " << g_color_heading << l_authdbname << g_color_default << "..." << std::endl;
			l_auth_svr.cmd_setph(l_authdbname, l_username, l_passphrasehash);
		}
			break;
		case 'c':
		{
			l_authdbname = std::string(optarg);
			if (!l_master_specified) {
				std::cout << g_color_highlight << "create:" << g_color_error << " must specify a master passphrase to seal/unseal auth DB." << g_color_default << std::endl;
				exit(EXIT_FAILURE);
			}
			std::cout << g_color_highlight << "create:" << g_color_default << " attempting to create new auth DB: " << g_color_heading << l_authdbname << g_color_default << "..." << std::endl;
			l_auth_svr.cmd_create(l_authdbname);
		}
			break;
		case 'a':
		{
			l_authdbname = std::string(optarg);
			if (!l_master_specified) {
				std::cout << g_color_highlight << "adduser:" << g_color_error << " must specify a master passphrase to seal/unseal auth DB." << g_color_default << std::endl;
				exit(EXIT_FAILURE);
			}
			if (!l_username_specified) {
				std::cout << g_color_highlight << "adduser:" << g_color_error << " must specify a user name to add." << g_color_default << std::endl;
				exit(EXIT_FAILURE);				
			}
			if (!l_passphrase_specified) {
				std::cout << g_color_highlight << "adduser:" << g_color_error << " must specify a passphrase for this user." << g_color_default << std::endl;
				exit(EXIT_FAILURE);				
			}
			std::cout << g_color_highlight << "adduser:" << g_color_default << " attempting to add user " << g_color_heading << l_username << g_color_default;
			std::cout << " with privilege level " << g_color_heading << l_privilege << g_color_default;
			std::cout << " on auth DB: " << g_color_heading << l_authdbname << g_color_default << "..." << std::endl;
			l_auth_svr.cmd_adduser(l_authdbname, l_username, l_passphrase, l_privilege);
		}
			break;
		case OPT_ADDUSERHASH:
		{
			l_authdbname = std::string(optarg);
			if (!l_master_specified) {
				std::cout << g_color_highlight << "adduserhash:" << g_color_error << " must specify a master passphrase to seal/unseal auth DB." << g_color_default << std::endl;
				exit(EXIT_FAILURE);
			}
			if (!l_username_specified) {
				std::cout << g_color_highlight << "adduserhash:" << g_color_error << " must specify a user name to add." << g_color_default << std::endl;
				exit(EXIT_FAILURE);				
			}
			if (!l_passphrasehash_specified) {
				std::cout << g_color_highlight << "adduserhash:" << g_color_error << " must specify a passphrase hash for this user." << g_color_default << std::endl;
				exit(EXIT_FAILURE);				
			}
			std::cout << g_color_highlight << "adduserhash:" << g_color_default << " attempting to add user " << g_color_heading << l_username << g_color_default;
			std::cout << " with privilege level " << g_color_heading << l_privilege << g_color_default;
			std::cout << " on auth DB: " << g_color_heading << l_authdbname << g_color_default << "..." << std::endl;
			l_auth_svr.cmd_adduserhash(l_authdbname, l_username, l_passphrasehash, l_privilege);
		}
			break;
		case 'd':
		{
			l_authdbname = std::string(optarg);
			if (!l_master_specified) {
				std::cout << g_color_highlight << "deluser:" << g_color_error << " must specify a master passphrase to seal/unseal auth DB." << g_color_default << std::endl;
				exit(EXIT_FAILURE);
			}
			if (!l_username_specified) {
				std::cout << g_color_highlight << "deluser:" << g_color_error << " must specify a user name to delete." << g_color_default << std::endl;
				exit(EXIT_FAILURE);				
			}
			std::cout << g_color_highlight << "deluser:" << g_color_default << " attempting to delete user " << g_color_heading << l_username << g_color_default << std::endl;
			l_auth_svr.cmd_deluser(l_authdbname, l_username);
		}
			break;
		case OPT_LISTPH:
		{
			l_listph = true;
		}
			break;
		case 'l':
		{
			l_authdbname = std::string(optarg);
			if (!l_master_specified) {
				std::cout << g_color_highlight << "list:" << g_color_error << " must specify a master passphrase to seal/unseal auth DB." << g_color_default << std::endl;
				exit(EXIT_FAILURE);
			}
			std::cout << g_color_highlight << "list:" << g_color_default << " attempting to list auth DB: " << g_color_heading << l_authdbname << g_color_default << "..." << std::endl;
			l_auth_svr.cmd_list(l_authdbname, l_listph);
		}
			break;
		case 'o':
		{
			if (!l_username_specified) {
				std::cout << g_color_highlight << "loginout:" << g_color_error << " must specify a user name to log in and out." << g_color_default << std::endl;
				exit(EXIT_FAILURE);
			}
			l_authdbname = std::string(optarg);
			if (!l_master_specified) {
				std::cout << g_color_highlight << "loginout:" << g_color_error << " must specify a master passphrase to seal/unseal auth DB." << g_color_default << std::endl;
				exit(EXIT_FAILURE);
			}
			std::cout << g_color_highlight << "loginout:" << g_color_default << " attempting to log user " << g_color_heading << l_username << g_color_default << " in and out on auth DB: " << g_color_heading << l_authdbname << g_color_default << "..." << std::endl;
			l_auth_svr.cmd_loginout(l_authdbname, l_username);
		}
			break;
		}
	}
	return 0;
}
