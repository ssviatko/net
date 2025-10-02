#include <iostream>
#include <string>
#include <optional>

#include "auth.h"

int main(int argc, char **argv)
{
	if (argc != 3) {
		std::cout << "usage: cpackgen <authdb> <username>" << std::endl;
		exit(EXIT_FAILURE);
	}
	
	std::string l_authdb = std::string(argv[1]);
	std::string l_user = std::string(argv[2]);
	ss::net::auth l_svr(ss::net::auth::role::SERVER);
	if(!l_svr.load_authdb(l_authdb)) {
		std::cout << "unable to load authdb " << l_authdb << std::endl;
		exit(EXIT_FAILURE);
	}
	std::optional<ss::net::challenge_pack> l_cpack = l_svr.challenge(l_user);
	if (l_cpack == std::nullopt) {
		std::cout << "unable to generate challenge pack" << std::endl;
		exit(EXIT_FAILURE);
	}
	std::cout << "session key      : " << l_cpack->session << std::endl;
	std::cout << "expected response: " << l_cpack->expected_response << std::endl;
	
	return 0;
}
