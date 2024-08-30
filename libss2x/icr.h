#ifndef ICREGISTRY_H
#define ICREGISTRY_H

#include <string>
#include <sstream>
#include <fstream>
#include <map>
#include <vector>
#include <algorithm>
#include <array>
#include <memory>

#include <cstdint>

namespace ss {

class icr {
	// singleton class: ctor, dtor, copy ctor and assignment operator are private
	icr();
	virtual ~icr();
	icr(const icr& a_icr); // no copying
	icr& operator=(const icr& a_icr) { return *this; } // no assignment

public:
	static icr& get();
	void restart();

	// set/get individual keys
	void set_keyvalue(const std::string& a_category, const std::string& a_key, const std::string& a_value);
	std::string keyvalue(const std::string& a_category, const std::string& a_key);

	// get lists of currently defined categories/keys and other info
	std::vector<std::string> categories();
	bool category_is_defined(const std::string& a_category);
	std::vector<std::string> keys_for_category(const std::string& a_category);
	bool key_is_defined(const std::string& a_category, const std::string& a_key);

	// file processing
	void read_file(const std::string& a_filename, bool update_on_close);
	std::vector<std::string> files();

	// argument processing
	void read_arguments(int argc, char **a_argv);
	size_t argc() const { return m_argv.size(); }
	std::string argv(uint32_t a_arg) { return m_argv[a_arg]; } // zero based arg list, including --set_keyvalue= parameters
	std::string exename() { return m_exename; } // executable file name from argv[0]

	// text formatting adaptor functions: extraction of data from registry
	bool to_boolean(const std::string& a_str); ///< Convert string to boolean representation.
	int64_t to_integer(const std::string& a_str); ///< Convert string to long long integer representation.
	double to_float(const std::string& a_str); ///< Convert string to double-precision floating point representation.
	std::string to_unformatted_string(const std::string& a_str); ///< Convert formatted string to unformatted string with embedded control characters.
	std::vector<std::string> to_string_list(const std::string& a_str); ///< Convert comma-delimited string list to vector of std::strings.

	// text formatting adaptor functions: preparation of data for insertion into registry
	std::string from_boolean(bool a_bool); ///< Convert boolean representation to string.
	std::string from_integer(int64_t a_int); ///< Convert long long integer to string.
	std::string from_float(double a_double); ///< Convert double precision floating point to string.
	std::string from_unformatted_string(const std::string& a_str); ///< Convert unformatted string to string with escape codes for control characters.
	std::string from_string_list(const std::vector<std::string>& a_vec); ///< Convert vector of strings into comma-delimited string list.

	// utility functions
	void trim_std_string(std::string& a_str); ///< Trim leading and trailing spaces from std::string.
	bool env_expand(std::string& a_str); ///< Expand tokens from defined environment variables.

protected:
	void shutdown();
	std::map<std::string, std::shared_ptr<std::map<std::string, std::string> > > m_categories;
	std::vector<std::string> m_files;
	void process_file(const std::string& a_filename, bool do_update);
	std::vector<std::string> m_argv;
	std::string m_exename;
};

} // namespace ss

#endif // ICREGISTRY_H
