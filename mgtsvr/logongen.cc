#include <iostream>
#include <string>

#include <cstdlib>

#include "data.h"

int main(int argc, char **argv)
{
	if (argc != 3) {
		std::cout << "usage: logongen <passphrase> <PIN>" << std::endl;
		exit(EXIT_FAILURE);
	}
	
	std::string l_pw = std::string(argv[1]);
	ss::data l_pwdata;
	l_pwdata.write_std_str(l_pw);
	ss::data l_pwhash = l_pwdata.sha2_512();
	std::cout << "base hash: " << l_pwhash.as_base64() << std::endl;
	std::uint16_t l_pin = std::atoi(argv[2]);
	std::cout << "PIN selected: " << l_pin << std::endl;

	return 0;
}
