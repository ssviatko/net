#include <iostream>
#include <string>

#include "auth.h"

int main(int argc, char **argv)
{
	if (argc != 3) {
		std::cout << "usage: crgen <session> <password>" << std::endl;
		exit(EXIT_FAILURE);
	}
	
	std::string l_sess = std::string(argv[1]);
	std::string l_pw = std::string(argv[2]);
	ss::net::auth l_cli(ss::net::auth::role::CLIENT);
	std::cout << l_cli.challenge_response(l_sess, l_pw).value() << std::endl;
	
	return 0;
}
