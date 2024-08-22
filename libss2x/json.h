#ifndef SSJSON_H
#define SSJSON_H

#include <string>

/*
 * SSJSON
 * 
 * Developed by Stephen Sviatko
 * Good Neighbors LLC
 * 
 * 14/May/2021
 * updated in August 2024 for ss2x library
 * 
 */

#include <iostream>
#include <string>
#include <sstream>
#include <memory>
#include <vector>
#include <map>
#include <stdexcept>
#include <cstdint>

namespace ss {
namespace json {

/* elements */

enum element_type {
	OBJECT,
	ARRAY,
	STRING,
	NUMBER,
	TRUE,
	FALSE,
	NULLELEMENT
};

class element {
public:
	element();
	element(const std::string& a_content, element_type a_type);
	virtual ~element();
	std::string content() { return m_content; }
	element_type type() { return m_type; }
	friend class parse_engine;
protected:
	std::string m_content;
	element_type m_type;
};

class constant : public element {
public:
	constant(element_type a_type);
	virtual ~constant();
};

class number : public element {
public:
	number();
	virtual ~number();
	number(const std::string& a_content);
	std::uint64_t as_uint();
	std::int64_t as_int();
	double as_float();
};

class string : public element {
public:
	string();
	virtual ~string();
	string(const std::string& a_content);
};

class object : public element {
public:
	object();
	virtual ~object();
	std::map<std::shared_ptr<string>, std::shared_ptr<element> > stringvalues;
};

class array : public element {
public:
	array();
	virtual ~array();
	std::vector<std::shared_ptr<element> > values;
};

class master {
public:
	master();
	~master();
	element_type type() { return m_masterelement->type(); }
	std::shared_ptr<object> as_object() { return std::dynamic_pointer_cast<object>(m_masterelement); }
	std::shared_ptr<array> as_array() { return std::dynamic_pointer_cast<array>(m_masterelement); }
	friend class parse_engine;
protected:
	// can be either an object or an array
	std::shared_ptr<element> m_masterelement;
};

/* state machines * parse engine */

enum parse_state {
	PS_FIND_MASTER,
	PS_COLLECT_OBJECT,
	PS_COLLECT_ARRAY
};

enum co_state {
	CO_FIND_STRING,
	CO_COLLECT_STRING,
	CO_FIND_VALUE,
	CO_COLLECT_VALUE,
	CO_FIND_TERMINATOR
};

enum cs_state {
	CS_COLLECT_CHAR
};

enum cv_state {
	CV_IDENTIFY_VALUE,
	CV_COLLECT_STRING,
	CV_COLLECT_NUMBER,
	CV_COLLECT_OBJECT,
	CV_COLLECT_ARRAY
};

enum cn_state {
	CN_COLLECT_FIRST
};

enum ca_state {
	CA_FIND_VALUE,
	CA_COLLECT_VALUE,
	CA_FIND_TERMINATOR
};

class parse_engine {
public:
	parse_engine(const std::string& a_json);
	~parse_engine();
	bool is_whitespace(char a_char);
	bool is_digit09(char a_char);
	bool is_digit19(char a_char);
	std::shared_ptr<string> collect_string();
	std::shared_ptr<number> collect_number();
	std::shared_ptr<element> collect_value();
	std::shared_ptr<array> collect_array();
	std::shared_ptr<object> collect_object();
	std::shared_ptr<master> parse();
protected:
	std::string m_json;
	std::string::iterator m_json_it;
	std::shared_ptr<master> m_master;
};

/* casting helpers */

std::shared_ptr<object> as_object(std::shared_ptr<element> a_element) { return std::dynamic_pointer_cast<object>(a_element); }
std::shared_ptr<array> as_array(std::shared_ptr<element> a_element) { return std::dynamic_pointer_cast<array>(a_element); }
std::shared_ptr<string> as_string(std::shared_ptr<element> a_element) { return std::dynamic_pointer_cast<string>(a_element); }
std::shared_ptr<number> as_number(std::shared_ptr<element> a_element) { return std::dynamic_pointer_cast<number>(a_element); }
std::shared_ptr<constant> as_constant(std::shared_ptr<element> a_element) { return std::dynamic_pointer_cast<constant>(a_element); }

/* typedefs to hide gory shared_ptr templating */

typedef std::shared_ptr<master> master_ptr;
typedef std::shared_ptr<object> object_ptr;
typedef std::shared_ptr<array> array_ptr;
typedef std::shared_ptr<string> string_ptr;
typedef std::shared_ptr<number> number_ptr;
typedef std::shared_ptr<constant> constant_ptr;
typedef std::shared_ptr<element> element_ptr;

/* functions */

std::shared_ptr<master> parse_json(const std::string& a_json);
std::string make_human_readable(std::string a_json); // format a JSON string with tabs and linefeeds

/* json serialization */

template <typename T>
std::string comma_list(const T& a_last) { return a_last; }
template <typename U, typename... T>
std::string comma_list(const U& a_first, const T&... a_other) { return a_first + std::string(", ") + comma_list(a_other...); }

class json_serializable {
public:
	json_serializable(const std::string& a_object_name, element_type a_type); // OBJECT or ARRAY supported
	~json_serializable();
	std::string& object_name() { return m_object_name; }
	std::string serialize();
	virtual std::string seal() = 0;
	static std::string master_object_enclose(const std::string& a_json);
	std::string stringvalue_number(const std::string& a_name, int a_num);
	std::string stringvalue_number(const std::string& a_name, double a_num);
	std::string stringvalue_string(const std::string& a_name, const std::string& a_string);
	std::string stringvalue_array(json_serializable& a_ser);
	std::string value_number(int a_num);
	std::string value_number(double a_num);
	std::string value_string(const std::string& a_string);
protected:
	std::string m_object_name;
	element_type m_type;
};

} // namespace json
} // namespace ss

#endif // SSJSON_H
