#ifndef AUTH_H
#define AUTH_H

#include <string>
#include <map>
#include <optional>

#include "data.h"
#include "doubletime.h"

namespace ss {
namespace net {

struct user_rec {
public:
	std::string username;
	std::string password_hash;
	bool logged_in; // not persistent
	ss::doubletime last_login; // last login time
	ss::doubletime last; // last seen time
};

struct challenge_pack {
public:
	std::string username;
	std::string session;
	std::string expected_response;
};

class auth {
	
	std::string generate_hash(const std::string& a_password);
	std::string generate_session();
	std::string generate_challenge(const std::string& a_session, const std::string a_password_hash);
	
public:

	enum role { CLIENT, SERVER };
	
	auth(role a_role);
	~auth();
	
	// client side
	std::optional<std::string> challenge_response(const std::string& a_session, const std::string& a_password);
	
	// server side
	bool add_user(const std::string& a_username, const std::string& a_password);
	std::optional<challenge_pack> challenge(const std::string a_username);
	bool authenticate(const std::string a_username, challenge_pack a_cpack, const std::string& a_response);
	bool logout(const std::string& a_username);
	
protected:
	role m_role;
	std::map<std::string, user_rec> m_user_records;
};

} // namespace net
} // namespace ss

#endif // AUTH_H
