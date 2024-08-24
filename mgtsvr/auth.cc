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
//	std::cout << "auth::challenge u=" << a_username << " sess=" << l_ret.session << " er=" << l_ret.expected_response << std::endl;
	return l_ret;
}

std::optional<std::string> auth::challenge_response(const std::string& a_session, const std::string& a_password)
{
	// client side only
	if (m_role != role::CLIENT)
		return std::nullopt;
	
	std::string l_pw_hash = generate_hash(a_password);
	std::string l_ret = generate_challenge(a_session, l_pw_hash);
//	std::cout << "auth::challenge response sess=" << a_session << " pwhash=" << l_pw_hash << " resp=" << l_ret << std::endl;
	return l_ret;
}

bool auth::change_pw_plaintext_pw(const std::string& a_username, const std::string& a_old_pw, const std::string& a_new_pw)
{
	// this only works in SERVER mode
	if (m_role != role::SERVER)
		return false;
		
	// check if this user already exists, return false if it's not there
	auto check_it = m_user_records.find(a_username);
	if (check_it == m_user_records.end())
		return false;
	
	return change_pw(a_username, generate_hash(a_old_pw), generate_hash(a_new_pw));
}

bool auth::change_pw(const std::string& a_username, const std::string& a_old_pw_hash, const std::string& a_new_pw_hash)
{
	// this only works in SERVER mode
	if (m_role != role::SERVER)
		return false;
		
	// check if this user already exists, return false if it's not there
	auto check_it = m_user_records.find(a_username);
	if (check_it == m_user_records.end())
		return false;
	
	if (check_it->second.password_hash == a_old_pw_hash) {
		check_it->second.password_hash = a_new_pw_hash;
//		std::cout << "auth::change_pw: u=" << a_username << " old=" << a_old_pw_hash << " new=" << a_new_pw_hash << std::endl;
		return true;
	}
	return false;
}

bool auth::add_user_plaintext_pw(const std::string& a_username, const std::string& a_password)
{
	// this only works in SERVER mode
	if (m_role != role::SERVER)
		return false;
		
	// check if this user already exists, return false if it's already there
	auto check_it = m_user_records.find(a_username);
	if (check_it != m_user_records.end())
		return false;
	
	std::string l_pw_hash = generate_hash(a_password);
	return add_user(a_username, l_pw_hash);
}

bool auth::add_user(const std::string& a_username, const std::string& a_password_hash)
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
	l_rec.password_hash = a_password_hash;
	l_rec.last_login = ss::doubletime(0.0);
	l_rec.last = ss::doubletime(0.0);
	l_rec.creation = ss::doubletime();
	l_rec.priv_level = 0; // standard user
//	std::cout << "add_user: " << l_rec.username << ", pw=" << l_rec.password_hash << std::endl;
	m_user_records.insert(std::pair<std::string, user_rec>(l_rec.username, l_rec));
	return true;
}

bool auth::delete_user(const std::string& a_username)
{
	// this only works in SERVER mode
	if (m_role != role::SERVER)
		return false;
		
	// check if this user already exists, return false if it's not there
	auto check_it = m_user_records.find(a_username);
	if (check_it == m_user_records.end())
		return false;
		
	m_user_records.erase(check_it);
	return true;
}

bool auth::set_priv_level(const std::string& a_username, int a_priv_level)
{
	// this only works in SERVER mode
	if (m_role != role::SERVER)
		return false;
		
	// check if this user already exists, return false if it's not there
	auto check_it = m_user_records.find(a_username);
	if (check_it == m_user_records.end())
		return false;
	
	check_it->second.priv_level = a_priv_level;
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

std::optional<bool> auth::logged_in(const std::string& a_username)
{
	// this only works in SERVER mode
	if (m_role != role::SERVER)
		return std::nullopt;
		
	// check if username exists, bail if not
	auto check_it = m_user_records.find(a_username);
	if (check_it == m_user_records.end())
		return std::nullopt;
	
	return check_it->second.logged_in;
}

std::optional<ss::doubletime> auth::last_login(const std::string& a_username)
{
	// this only works in SERVER mode
	if (m_role != role::SERVER)
		return std::nullopt;
		
	// check if username exists, bail if not
	auto check_it = m_user_records.find(a_username);
	if (check_it == m_user_records.end())
		return std::nullopt;
	
	return check_it->second.last_login;
}

std::optional<ss::doubletime> auth::last(const std::string& a_username)
{
	// this only works in SERVER mode
	if (m_role != role::SERVER)
		return std::nullopt;
		
	// check if username exists, bail if not
	auto check_it = m_user_records.find(a_username);
	if (check_it == m_user_records.end())
		return std::nullopt;
	
	return check_it->second.last;
}

std::optional<ss::doubletime> auth::creation(const std::string& a_username)
{
	// this only works in SERVER mode
	if (m_role != role::SERVER)
		return std::nullopt;
		
	// check if username exists, bail if not
	auto check_it = m_user_records.find(a_username);
	if (check_it == m_user_records.end())
		return std::nullopt;
	
	return check_it->second.creation;
}

std::optional<int> auth::priv_level(const std::string& a_username)
{
	// this only works in SERVER mode
	if (m_role != role::SERVER)
		return std::nullopt;
		
	// check if username exists, bail if not
	auto check_it = m_user_records.find(a_username);
	if (check_it == m_user_records.end())
		return std::nullopt;
	
	return check_it->second.priv_level;
}

bool auth::load_authdb(const std::string& a_filename)
{
	// this only works in SERVER mode
	if (m_role != role::SERVER)
		return false;
	
	// file exists?
	if (!std::filesystem::exists(a_filename))
		return false;
		
	ss::data l_load;
	l_load.load_file(a_filename.c_str());
	std::string l_work = l_load.read_std_str(l_load.size());
		
	std::shared_ptr<ss::json::master> l_master = ss::json::parse_json(l_work);
	if (l_master->type() == ss::json::element_type::OBJECT) {
		m_user_records.clear();
		std::shared_ptr<ss::json::object> l_root_object = l_master->as_object();
		for (const auto& i : l_root_object->stringvalues) {
			if (i.first->content() == "auth_db") {
//				std::cout << "found auth_db" << std::endl;
				if (i.second->type() == ss::json::element_type::ARRAY) {
					std::shared_ptr<ss::json::array> l_user_array = ss::json::as_array(i.second);
					for (const auto& j : l_user_array->values) {
						if (j->type() == ss::json::element_type::OBJECT) {
							std::shared_ptr<ss::json::object> jj = ss::json::as_object(j);
							user_rec l_user;
							for (const auto& k : jj->stringvalues) {
								if (k.first->content() == "username") {
//									std::cout << "found username: " << k.second->content() << std::endl;
									l_user.username = k.second->content();
								}
								if (k.first->content() == "password_hash") {
//									std::cout << "found password_hash: " << k.second->content() << std::endl;
									l_user.password_hash = k.second->content();
								}
								if (k.first->content() == "last_login") {
//									std::cout << "found last_login: " << ss::json::as_number(k.second)->as_float() << std::endl;
									l_user.last_login = ss::doubletime(ss::json::as_number(k.second)->as_float());
								}
								if (k.first->content() == "last") {
//									std::cout << "found last: " << ss::json::as_number(k.second)->as_float() << std::endl;
									l_user.last = ss::doubletime(ss::json::as_number(k.second)->as_float());
								}
								if (k.first->content() == "creation") {
									l_user.creation = ss::doubletime(ss::json::as_number(k.second)->as_float());
								}
								if (k.first->content() == "priv_level") {
									l_user.priv_level = ss::json::as_number(k.second)->as_int();
								}
							}
							m_user_records.insert(std::pair<std::string, user_rec>(l_user.username, l_user));
						}
					}
				}
			}
		}
		return true;
	}
	return false;
}

bool auth::save_authdb(const std::string& a_filename)
{
	// this only works in SERVER mode
	if (m_role != role::SERVER)
		return false;
		
	// if DB is empty, do nothing
	if (m_user_records.size() == 0)
		return false;

	std::string l_work;
	l_work += "{ \"auth_db\": [ ";
	for (const auto& [key, value] : m_user_records) {
		l_work += "{ ";
		l_work += "\"username\": \"" + value.username + "\", ";
		l_work += "\"password_hash\": \"" + value.password_hash + "\", ";
		l_work += "\"last_login\": " + std::format("{}", double(value.last_login)) + ", ";
		l_work += "\"last\": " + std::format("{}", double(value.last)) + ", ";
		l_work += "\"creation\": " + std::format("{}", double(value.creation)) + ", ";
		l_work += "\"priv_level\": " + std::format("{}", value.priv_level) + " ";
		l_work += "}, ";
	}
	// trim final comma
	std::string::iterator l_it = l_work.end() - 2;
	l_work.erase(l_it, l_work.end());
	l_work += " ] }";
//	std::cout << "save_authdb: " << ss::json::make_human_readable(l_work) << std::endl;
	ss::data l_save;
	l_save.write_std_str(ss::json::make_human_readable(l_work));
	l_save.save_file(a_filename.c_str());
	return true;
}

} // namespace net
} // namespace ss

