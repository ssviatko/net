#ifndef DISPATCHABLE_H
#define DISPATCHABLE_H

#include <string>
#include <thread>
#include <semaphore>
#include <mutex>
#include <chrono>

#include "log.h"

namespace ss {
namespace ccl {

class dispatchable {
public:
	dispatchable(const std::string& a_logname);
	virtual ~dispatchable();
	void start();
	void halt();
	void snooze();
	virtual bool dispatch() = 0;
	virtual void starting();
	virtual void started();
	virtual void halting();
	virtual void halted();
	
protected:
	void dispatch_core();
	bool m_dispatch_running;
	std::string m_thread_name;
	ss::log::ctx& ctx = ss::log::ctx::get();
	std::binary_semaphore m_dispatchthr_started { 0 };
	std::binary_semaphore m_dispatchthr_stopped { 0 };
};

} // namespace ccl
} // namespace ss

#endif // DISPATCHABLE_H
