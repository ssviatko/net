#include "auth.h"

namespace ss {
namespace net {

auth::auth(role a_role)
: m_role(a_role)
{
	
}

auth::~auth()
{
	
}

std::string auth::generate_hash(const std::string& a_password)
{
	ss::data l_pw;
	l_pw.write_std_str(a_password);
	ss::data l_pw_hash = l_pw.sha2_384();
	std::string l_ret = l_pw_hash.as_base64();
	return l_ret;
}

std::string auth::generate_session()
{
	ss::data l_rand;
	l_rand.random(1024);
	ss::data l_session_hash = l_rand.sha2_384();
	std::string l_ret = l_session_hash.as_base64();
	return l_ret;
}

std::string auth::generate_challenge(const std::string& a_session, const std::string a_password_hash)
{
	ss::data l_work;
	l_work.write_base64(a_session);
	l_work.write_base64(a_password_hash);
	ss::data l_chal_hash = l_work.sha2_384();
	std::string l_ret = l_chal_hash.as_base64();
	return l_ret;
}

std::optional<challenge_pack> auth::challenge(const std::string a_username)
{
	// server side only
	if (m_role != role::SERVER)
		return std::nullopt;
		
	// check if username exists, nullopt if not
	auto check_it = m_user_records.find(a_username);
	if (check_it == m_user_records.end())
		return std::nullopt;
		
	// user exists, so populate a challenge_pack
	challenge_pack l_ret;
	l_ret.username = a_username;
	l_ret.session = generate_session();
	l_ret.expected_response = generate_challenge(l_ret.session, check_it->second.password_hash);
	std::cout << "auth::challenge u=" << a_username << " sess=" << l_ret.session << " er=" << l_ret.expected_response << std::endl;
	return l_ret;
}

std::optional<std::string> auth::challenge_response(const std::string& a_session, const std::string& a_password)
{
	// client side only
	if (m_role != role::CLIENT)
		return std::nullopt;
	
	std::string l_pw_hash = generate_hash(a_password);
	std::string l_ret = generate_challenge(a_session, l_pw_hash);
	std::cout << "auth::challenge response sess=" << a_session << " pwhash=" << l_pw_hash << " resp=" << l_ret << std::endl;
	return l_ret;
}

bool auth::add_user(const std::string& a_username, const std::string& a_password)
{
	// this only works in SERVER mode
	if (m_role != role::SERVER)
		return false;
		
	// check if this user already exists, return false if it's already there
	auto check_it = m_user_records.find(a_username);
	if (check_it != m_user_records.end())
		return false;
		
	user_rec l_rec;
	l_rec.username = a_username;
	l_rec.password_hash = generate_hash(a_password);
	std::cout << "add_user: " << l_rec.username << ", pw=" << l_rec.password_hash << std::endl;
	m_user_records.insert(std::pair<std::string, user_rec>(l_rec.username, l_rec));
	return true;
}

bool auth::authenticate(const std::string a_username, challenge_pack a_cpack, const std::string& a_response)
{
	// many ways this can fail.
	// this only works in SERVER mode
	if (m_role != role::SERVER)
		return false;
		
	// check if username exists, bail if not
	auto check_it = m_user_records.find(a_username);
	if (check_it == m_user_records.end())
		return false;
		
	// compare the expected_response with the client's response. bail if they differ
	if (a_cpack.expected_response != a_response)
		return false;
		
	// success! log user in.
	check_it->second.logged_in = true;
	check_it->second.last_login = ss::doubletime();
	return true;
}

bool auth::logout(const std::string& a_username)
{
	// this only works in SERVER mode
	if (m_role != role::SERVER)
		return false;
		
	// check if username exists, bail if not
	auto check_it = m_user_records.find(a_username);
	if (check_it == m_user_records.end())
		return false;
		
	// check if user is even logged in
	if (!(check_it->second.logged_in))
		return false;
		
	// log out the user
	check_it->second.logged_in = false;
	check_it->second.last = ss::doubletime();
	return true;
}

} // namespace net
} // namespace ss

