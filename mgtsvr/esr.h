#ifndef ESR_H
#define ESR_H

#include <string>
#include <map>
#include <vector>
#include <memory>

namespace ss {

enum esr_item_type {
	OBJECT,
	ARRAY,
	STRING,
	NUMBER,
	BOOLEAN
};

// item classes - base

class esr_base {
public:
	esr_base(const std::string& a_name, ss::esr_item_type a_type);
	virtual ~esr_base();
	std::string name;
	esr_item_type type;
};
	
// all items are either a value or a container

template <typename T>
class esr_value : public esr_base {
public:
	esr_value(const std::string& a_name, ss::esr_item_type a_type, T a_value);
	virtual ~esr_value();
	T value;
};
	
template <typename T>
esr_value<T>::esr_value(const std::string& a_name, ss::esr_item_type a_type, T a_value)
: esr_base(a_name, a_type)
, value(a_value)
{ }

template <typename T>
esr_value<T>::~esr_value()
{ }

template <typename T>
class esr_container : public esr_base {
public:
	esr_container(const std::string& a_name, ss::esr_item_type a_type);
	virtual ~esr_container();
	T container;
};

template <typename T>
esr_container<T>::esr_container(const std::string& a_name, ss::esr_item_type a_type)
: esr_base(a_name, a_type)
{ }

template <typename T>
esr_container<T>::~esr_container()
{ }

// value types

class esr_string : public esr_value<std::string> {
public:
	esr_string(const std::string& a_name, const std::string& a_value);
	virtual ~esr_string();
};

class esr_number : public esr_value<double> {
public:
	esr_number(const std::string& a_name, double a_value);
	virtual ~esr_number();
};

class esr_boolean : public esr_value<bool> {
public:
	esr_boolean(const std::string& a_name, bool a_value);
	virtual ~esr_boolean();
};
	
// convenience typedefs

typedef std::shared_ptr<esr_base> esr_base_ptr;
typedef std::shared_ptr<esr_string> esr_string_ptr;
typedef std::shared_ptr<esr_number> esr_number_ptr;
typedef std::shared_ptr<esr_boolean> esr_boolean_ptr;
typedef std::map<std::string, esr_base_ptr> object_cont;
typedef std::vector<esr_base_ptr> array_cont;

// container types

class esr_object : public esr_container<object_cont> {
public:
	esr_object(const std::string& a_name);
	virtual ~esr_object();
};

class esr_array : public esr_container<array_cont> {
public:
	esr_array(const std::string& a_name);
	virtual ~esr_array();
};

typedef std::shared_ptr<esr_object> esr_object_ptr;
typedef std::shared_ptr<esr_array> esr_array_ptr;

// casting helpers

esr_object_ptr as_object(esr_base_ptr a_item);
esr_array_ptr as_array(esr_base_ptr a_item);
esr_string_ptr as_string(esr_base_ptr a_item);
esr_number_ptr as_number(esr_base_ptr a_item);
esr_boolean_ptr as_boolean(esr_base_ptr a_item);

// esr

class esr {
public:
	// constructors
	esr();
	virtual ~esr();
	
protected:
	esr_object_ptr m_root;
};

} // namespace ss

#endif // ESR_H
