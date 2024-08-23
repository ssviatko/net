#include <iostream>
#include <string>
#include <format>
#include <optional>

#include "auth.h"

int main(int argc, char **argv)
{
	std::string l_pw = "banana";
	
	// add user to server user database. This is done locally and is not exposed.
	ss::net::auth l_svr(ss::net::auth::role::SERVER);
	bool l_add_user_success = l_svr.add_user("ssviatko", l_pw);
	std::cout << std::format("add_user: {}", l_add_user_success) << std::endl;
	
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
	// log the user out
	bool l_logout_success = l_svr.logout("ssviatko");
	std::cout << std::format("logout: {}", l_logout_success) << std::endl;
	
	return 0;
}