#include <iostream>
#include <iomanip>
#include <string>

#include <cstdlib>

#include "data.h"

std::string g_version = "1.0";
std::string g_allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
std::uint32_t g_allowed_len = g_allowed.size();

int main(int argc, char **argv)
{
	if (argc != 3) {
		std::cout << "usage: logongen <passphrase> <PIN>" << std::endl;
		exit(EXIT_FAILURE);
	}

	std::uint16_t l_pin = std::atoi(argv[2]);
	if ((l_pin < 1000) || (l_pin > 9999)) {
		std::cout << "PIN must be a 4 digit number." << std::endl;
		exit(EXIT_FAILURE);
	}
	
	std::cout << "logongen version: " << g_version << std::endl;
	std::cout << "allowed characters: " << g_allowed << " (" << g_allowed_len << " characters)" << std::endl;
	std::cout << "PIN selected: " << l_pin << std::endl;

	std::string l_pw = std::string(argv[1]);
	ss::data l_pwdata;
	l_pwdata.write_std_str(l_pw);
	ss::data l_pwhash = l_pwdata.sha2_512();
	std::cout << "base hash: " << l_pwhash.as_base64() << std::endl;

	// generate forward hash
	ss::data l_forwardhash = l_pwhash;
	for (unsigned int i = 1; i <= l_pin; ++i) {
		ss::data l_new = l_forwardhash.sha2_512();
		l_forwardhash = l_new;
	}
	std::cout << "forward hash: " << l_forwardhash.as_base64() << std::endl;
	
	std::string l_pwout;

	// generate first char with a modulus of 26, make it a capital letter
	std::uint32_t l_capnum = l_forwardhash.read_uint32();
	std::uint8_t l_capmodulus = l_capnum % 26;
	l_pwout += g_allowed.at(l_capmodulus);

	// generate second char with a modulus of 10, make it a number
	std::uint32_t l_numnum = l_forwardhash.read_uint32();
	std::uint8_t l_nummodulus = l_numnum % 10;
	l_nummodulus += 52; // step over all the letters
	l_pwout += g_allowed.at(l_nummodulus);

	// generate third char with modulus of 26, mandatory lower case letter
	std::uint32_t l_lowernum = l_forwardhash.read_uint32();
	std::uint8_t l_lowermodulus = l_lowernum % 26;
	l_lowermodulus += 26; // step over the caps
	l_pwout += g_allowed.at(l_lowermodulus);

	// generate 4th char as a special char
	std::uint32_t l_specialnum = l_forwardhash.read_uint32();
	std::uint8_t l_specialmodulus = l_specialnum % (g_allowed_len - 62);
	l_specialmodulus += 62; // step over letters and numbers
	l_pwout += g_allowed.at(l_specialmodulus);

	// remaining characters are random from any point in the allowed character list
	for (unsigned int i = 4; i < 16; ++i) {
		std::uint32_t l_num = l_forwardhash.read_uint32();
		std::uint8_t l_modulus = l_num % g_allowed_len;
//		std::cout << "numeric " << i << ": " << std::hex << l_num << " modulus: " << std::dec << (int)l_modulus << std::endl;
		l_pwout += g_allowed.at(l_modulus);
	}
	std::cout << "generated password: " << l_pwout << std::endl;

	return 0;
}
