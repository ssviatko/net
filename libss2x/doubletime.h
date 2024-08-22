#ifndef DOUBLETIME_H
#define DOUBLETIME_H

#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <chrono>
#include <format>
#include <array>

#include <cstdint>
#include <ctime>
#include <cmath>
#include <cstring>

namespace ss {
	
const std::array<std::string, 7> weekdays = { "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday" };
const std::array<std::string, 7> weekdays_abbrev = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
const std::array<std::string, 12> months = { "January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December" };
const std::array<std::string, 12> months_abbrev = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

class doubletime {
	
	// private utility functions used by other methods
	std::string iso8601_utility(bool a_islocal, unsigned int a_trim);
	void eat(const doubletime& a_doubletime); // guts of copy constructor/assignment operator
	void get_tm(bool a_islocal);
	
public:

	// constructors, destructor
	doubletime();
	doubletime(const double a_double);
	doubletime(const long double a_long_double);
	doubletime(const doubletime& a_doubletime);
	doubletime(const std::int64_t a_epoch);
	doubletime(doubletime&& a_doubletime);
	~doubletime();
	
	// utility functions
	void now();
	bool yet(); // have we reached this time yet? true = in the past, false = not yet
	bool yet(long double a_increment); // have we reached now + time in seconds yet?
	
	// setters
	void set_time(unsigned int a_year, unsigned int a_month, unsigned int a_day, unsigned int a_hour, unsigned int a_minute, unsigned int a_second);
	void set_time_epoch_seconds(std::int64_t a_epoch);
	void set_time_doubletime(double a_time);
	void set_time_long_doubletime(long double a_time);
	void delta_time_doubletime(double a_time); // add/subtract a_time from time
	void delta_time_long_doubletime(long double a_time);
	
	// getters
	std::int64_t epoch_seconds() const { return m_sec; }
	std::uint64_t epoch_nanoseconds() const { return m_ns; }
	unsigned int zulu_year();
	unsigned int local_year();
	unsigned int zulu_month();
	unsigned int local_month();
	std::string month_name(unsigned int a_month) const { return months[a_month - 1]; }
	std::string month_name_abbrev(unsigned int a_month) const { return months_abbrev[a_month - 1]; }
	unsigned int zulu_day();
	unsigned int local_day();
	unsigned int zulu_day_of_week();
	unsigned int local_day_of_week();
	std::string weekday_name(unsigned int a_day) const { return weekdays[a_day]; }
	std::string weekday_name_abbrev(unsigned int a_day) const { return weekdays_abbrev[a_day]; }
	unsigned int zulu_hour();
	unsigned int local_hour();
	unsigned int zulu_minute();
	unsigned int local_minute();
	unsigned int zulu_second();
	unsigned int local_second();
	unsigned int zulu_day_of_year();
	unsigned int local_day_of_year();
	bool is_dst(); // assumes local time
	double gmtoff(); // assumes local time
	std::string tzstr(); // time zone string

	// iso8601 time stamps
	std::string iso8601_ms();
	std::string iso8601_us();
	std::string iso8601_ns();
	std::string iso8601_ms_zulu();
	std::string iso8601_us_zulu();
	std::string iso8601_ns_zulu();
	
	// operator overloads
	operator long int() const { return m_sec; }
	operator double() const { return (double)m_time; }
	operator long double() const { return m_time; }
	doubletime& operator=(const doubletime& a_doubletime);
	doubletime& operator=(doubletime&& a_doubletime);
	doubletime& operator=(const double a_double);
	doubletime& operator=(const long double a_long_double);
	doubletime& operator=(const std::int64_t a_epoch);
	
	// static helper methods
	static std::string now_as_iso8601_ms();
	static std::string now_as_iso8601_us();
	static std::string now_as_iso8601_ns();
	static std::string now_as_iso8601_ms_zulu();
	static std::string now_as_iso8601_us_zulu();
	static std::string now_as_iso8601_ns_zulu();
	static std::int64_t now_as_epoch_seconds();
	static double now_as_double();
	static long double now_as_long_double();
	static std::string now_as_file_stamp();
	
	// printing and formatting
	friend std::ostream& operator<<(std::ostream &os, doubletime& a_dt); // local

protected:
	std::chrono::system_clock::time_point m_tp;
	std::chrono::nanoseconds m_epoch;
	std::int64_t m_sec;
	std::uint64_t m_ns;
	long double m_time;
	struct tm m_tm; // used by get_tm for breakouts
};

} // namespace ss

template <>
struct std::formatter<ss::doubletime> {
	constexpr auto parse(std::format_parse_context& ctx) {
		m_is_zulu = false;
		auto pos = ctx.begin();
		while (pos != ctx.end() && *pos != '}') {
			if (*pos == 'Z')
				m_is_zulu = true;
			++pos;
		}
		return pos;
	}

	auto format(ss::doubletime& obj, std::format_context& ctx) const {
		if (m_is_zulu)
			return std::format_to(ctx.out(), "{}-{}-{} {:0>2}:{:0>2}:{:0>2}", obj.zulu_year(), obj.month_name_abbrev(obj.zulu_month()), obj.zulu_day(), obj.zulu_hour(), obj.zulu_minute(), obj.zulu_second());
		else
			return std::format_to(ctx.out(), "{}-{}-{} {:0>2}:{:0>2}:{:0>2}", obj.local_year(), obj.month_name_abbrev(obj.local_month()), obj.local_day(), obj.local_hour(), obj.local_minute(), obj.local_second());
	}

	bool m_is_zulu;
};

#endif // DOUBLETIME_H
