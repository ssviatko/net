#include <iostream>
#include <string>
#include <format>
#include <optional>

#include "auth.h"

int main(int argc, char **argv)
{
	std::string l_pw = "banana";
	std::string l_new_pw = "bohica";
	
	ss::net::auth l_svr(ss::net::auth::role::SERVER);
	bool l_load_success = l_svr.load_authdb("auth_db.json");
	std::cout << std::format("load_authdb: {}", l_load_success) << std::endl;

	// add user to server user database. This is done locally and is not exposed.
	bool l_add_user_success = l_svr.add_user_plaintext_pw("ssviatko", l_pw);
	std::cout << std::format("add_user_plaintext_pw: {}", l_add_user_success) << std::endl;
	// give user root privileges
	bool l_set_privs = l_svr.set_priv_level("ssviatko", -1);
	std::cout << std::format("set_priv_level: {}", l_set_privs) << std::endl;
	
	// user wants to login, so generate a challenge on the server side.
	// The session hash is randomly generated and goes over the wire to the client.
	auto l_chal = l_svr.challenge("ssviatko");
	if (!l_chal.has_value()) {
		std::cerr << "can't generate challenge pack" << std::endl;
		exit(EXIT_FAILURE);
	}
	// on the client side, we spin up an auth instance and generate a response based on
	// the session hash we were sent and the password hash which we generate locally.
	// together these produce a response hash which is sent over the wire back to the server.
	ss::net::auth l_cli(ss::net::auth::role::CLIENT);
	auto l_resp = l_cli.challenge_response(l_chal.value().session, l_pw);
	if (!l_resp.has_value()) {
		std::cerr << "can't generate challenge response" << std::endl;
		exit(EXIT_FAILURE);
	}
	// server compares the client's response hash against the expected response contained
	// in our server-side challenge_pack. If they match then the user is logged in.
	bool l_auth_success = l_svr.authenticate("ssviatko", l_chal.value(), l_resp.value());
	std::cout << std::format("authenticated: {}", l_auth_success) << std::endl;
	auto l_last_login = l_svr.last_login("ssviatko");
	if (l_last_login.has_value()) {
		std::cout << std::format("last login time: {}", l_last_login.value().iso8601_us()) << std::endl;
	}
	auto l_last = l_svr.last("ssviatko");
	if (l_last.has_value()) {
		std::cout << std::format("last seen time: {}", l_last.value().iso8601_us()) << std::endl;
	}
	// log the user out
	bool l_logout_success = l_svr.logout("ssviatko");
	std::cout << std::format("logout: {}", l_logout_success) << std::endl;
	// change the user's password
	std::string l_old = l_svr.generate_hash(l_pw);
	std::string l_new = l_svr.generate_hash(l_new_pw);
	bool l_change_pw_success = l_svr.change_pw("ssviatko", l_old, l_new);
	std::cout << std::format("change_pw: {}", l_change_pw_success) << std::endl;
	// change it back
	bool l_changeback_pw_success = l_svr.change_pw_plaintext_pw("ssviatko", l_new_pw, l_pw);
	std::cout << std::format("change_pw back: {}", l_changeback_pw_success) << std::endl;
	// delete the user
//	bool l_delete_user_success = l_svr.delete_user("ssviatko");
//	std::cout << std::format("delete_user: {}", l_delete_user_success) << std::endl;
	
	// add fresh user (if not already existing) for persistency
	bool l_persistent_user_success = l_svr.add_user("persist", l_new);
	std::cout << std::format("add_user: (persistent) {}", l_persistent_user_success) << std::endl;
	// save
	bool l_save_success = l_svr.save_authdb("auth_db.json");
	std::cout << std::format("save_authdb: {}", l_save_success) << std::endl;
	
	return 0;
}