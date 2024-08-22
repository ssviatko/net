#ifndef FS_H
#define FS_H

#include <iostream>
#include <string>
#include <unordered_map>
#include <stdexcept>
#include <format>
#include <stacktrace>
#include <functional>

#include <signal.h>

namespace ss {

const std::unordered_map<int, std::string> signal_map = {
	{ SIGABRT, "SIGABRT" },
	{ SIGBUS, "SIGBUS" },
	{ SIGFPE, "SIGFPE" },
	{ SIGILL, "SIGILL" },
	{ SIGSEGV, "SIGSEGV" },
	{ SIGSYS, "SIGSYS" },
	{ SIGTRAP, "SIGTRAP" },
	{ SIGXCPU, "SIGXCPU" },
	{ SIGXFSZ, "SIGXFSZ" },
	{ SIGINT, "SIGINT" },
	{ SIGHUP, "SIGHUP" },
	{ SIGTERM, "SIGTERM" }
};

class failure_services {
	
	// private because this is a singleton
	failure_services();
	~failure_services();
	static void handle_signal(int signo);

public:
	static failure_services& get();
	void install_signal_handler();
	void install_sigint_handler(std::function<void(void)> a_handler);
	void invoke_sigint_handler();
	void temporarily_ignore_signals();
	void unignore_signals();
	
protected:
	bool m_handler_installed;
	bool m_ignoring_signals;
	
	// SIGINT stuff
	static bool sigint_handler_installed;
	static std::function<void(void)> sigint_handler;
};

} // namespace ss

#endif // FS_H
