#ifndef AUTH_H
#define AUTH_H

#include <string>
#include <map>
#include <optional>
#include <memory>
#include <filesystem>
#include <thread>
#include <mutex>

#include "data.h"
#include "doubletime.h"
#include "json.h"

namespace ss {
namespace net {

struct user_rec {
public:
	std::string username;
	std::string password_hash;
	bool logged_in; // not persistent
	ss::doubletime last_login; // last login time
	ss::doubletime last; // last seen time
	ss::doubletime creation; // creation date/time
	int priv_level; // privelege level - lower is better. use 1+..=chumps, 0=normal user, -1=admins, -2...lower for super users
};

struct challenge_pack {
public:
	std::string username;
	std::string session;
	std::string expected_response;
};

class auth {
	
	std::string generate_session();
	std::string generate_challenge(const std::string& a_session, const std::string a_password_hash);
	
public:

	enum role { CLIENT, SERVER };
	
	auth(role a_role);
	~auth();
	
	// client side
	std::optional<std::string> challenge_response(const std::string& a_session, const std::string& a_password);
	
	// server side
	// WARNING: Do not use add_user variants over the wire, exposing the PW hash will make system vulnerable to a replay attack
	// Users should be added and passwords changed through a secure venue, e.g. users should supply their password hashes to an
	// admin through some secure means,
	// This is the entire point of the challenge/response mechanism, so an eavesdropper will not be able to determine the password
	// or the hash!
	bool add_user(const std::string& a_username, const std::string& a_password_hash);
	bool add_user_plaintext_pw(const std::string& a_username, const std::string& a_password);
	bool delete_user(const std::string& a_username);
	std::string generate_hash(const std::string& a_password);
	// WARNING: Do not use change_pw variants over the wire, exposing the PW hash will make system vulnerable to a replay attack
	bool change_pw(const std::string& a_username, const std::string& a_old_pw_hash, const std::string& a_new_pw_hash);
	bool change_pw_plaintext_pw(const std::string& a_username, const std::string& a_old_pw, const std::string& a_new_pw);
	std::optional<challenge_pack> challenge(const std::string a_username);
	bool authenticate(const std::string a_username, challenge_pack a_cpack, const std::string& a_response);
	bool logout(const std::string& a_username);
	bool set_priv_level(const std::string& a_username, int a_priv_level);
	std::optional<bool> logged_in(const std::string& a_username);
	std::optional<ss::doubletime> last_login(const std::string& a_username);
	std::optional<ss::doubletime> last(const std::string& a_username);
	std::optional<ss::doubletime> creation(const std::string& a_username);
	std::optional<int> priv_level(const std::string& a_username);
	// WARNING: In spite of being in JSON format, auth DB is not user editable!
	// doing so is not only a violation of security policies, but could also result in a syntactical error in the JSON
	// file which will result in exceptions or even segfaults when loading.
	bool load_authdb(const std::string& a_filename);
	bool save_authdb(const std::string& a_filename);
	
protected:
	role m_role;
	std::map<std::string, user_rec> m_user_records;
	std::mutex m_user_records_mtx;
};

} // namespace net
} // namespace ss

#endif // AUTH_H
