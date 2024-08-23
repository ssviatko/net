#include <iostream>
#include <string>

#include "auth.h"

int main(int argc, char **argv)
{
	if (argc != 2) {
		std::cout << "usage: pwgen <password>" << std::endl;
		exit(EXIT_FAILURE);
	}
	
	std::string l_pw = std::string(argv[1]);
	ss::net::auth l_cli(ss::net::auth::role::CLIENT);
	std::cout << l_cli.generate_hash(l_pw) << std::endl;
	
	return 0;
}
