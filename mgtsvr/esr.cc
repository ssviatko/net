#include "esr.h"

namespace ss {

// esr items

esr_base::esr_base(const std::string& a_name, ss::esr_item_type a_type)
: name(a_name)
, type(a_type)
{
	
}

esr_base::~esr_base()
{
	
}

// value types

esr_string::esr_string(const std::string& a_name, const std::string& a_value)
: esr_value(a_name, esr_item_type::STRING, a_value)
{
	
}

esr_string::~esr_string()
{
	
}

esr_number::esr_number(const std::string& a_name, double a_value)
: esr_value(a_name, esr_item_type::NUMBER, a_value)
{
	
}

esr_number::~esr_number()
{
	
}

esr_boolean::esr_boolean(const std::string& a_name, bool a_value)
: esr_value(a_name, esr_item_type::BOOLEAN, a_value)
{
	
}

esr_boolean::~esr_boolean()
{
	
}

// container types

esr_object::esr_object(const std::string& a_name)
: esr_container<object_cont>(a_name, esr_item_type::OBJECT)
{
	
}

esr_object::~esr_object()
{
	
}

void esr_object::add(esr_base_ptr a_item)
{
	// check if item with the same name is already in here, throw exception if it is
	
	// add the item
	container.insert(std::pair<std::string, esr_base_ptr>(a_item->name, a_item));
}

esr_array::esr_array(const std::string& a_name)
: esr_container<array_cont>(a_name, esr_item_type::ARRAY)
{
	
}

esr_array::~esr_array()
{
	
}

esr_object_ptr as_object(esr_base_ptr a_item) { return std::dynamic_pointer_cast<esr_object>(a_item); }
esr_array_ptr as_array(esr_base_ptr a_item) { return std::dynamic_pointer_cast<esr_array>(a_item); }
esr_string_ptr as_string(esr_base_ptr a_item) { return std::dynamic_pointer_cast<esr_string>(a_item); }
esr_number_ptr as_number(esr_base_ptr a_item) { return std::dynamic_pointer_cast<esr_number>(a_item); }
esr_boolean_ptr as_boolean(esr_base_ptr a_item) { return std::dynamic_pointer_cast<esr_boolean>(a_item); }

// esr

esr::esr()
{
	m_root = std::make_shared<esr_object>("root");
	m_root->add(new_value<esr_string, std::string>("build_number", BUILD_NUMBER));
	m_root->add(new_value<esr_string, std::string>("build_date", BUILD_DATE));
	m_root->add(new_value<esr_string, std::string>("release_number", RELEASE_NUMBER));
}

esr::~esr()
{
	
}

} // namespace ss
