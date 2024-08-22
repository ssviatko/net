#ifndef CCL_H
#define CCL_H

#include <string>
#include <deque>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <semaphore>
#include <atomic>
#include <chrono>
#include <optional>
#include <atomic>

#include "log.h"

namespace ss {
namespace ccl {

class thread {
	void execute_core();
	void copy_construct(const thread& a_thread);
	
public:
	thread(const std::string& a_logname);
	thread(const thread& a_thread) = delete;
	thread(thread&& a_thread) = delete;
	void start();
	virtual void execute() = 0;
	void request_stop();
	bool is_stop_requested();
	void join();
	void trigger();
	bool wait_for_trigger();

protected:
	std::thread m_thread;
	std::string m_thread_name;
	std::atomic<bool> m_stop_requested;
	ss::log::ctx& ctx = ss::log::ctx::get();
	void snooze();
	std::binary_semaphore m_trigger { 0 };
};

// ss::ccl::work_queue

template <typename T>
class work_queue {
	// no copying or moving
	work_queue(const work_queue<T>& a_other_queue);
	work_queue<T>& operator=(const work_queue<T>& a_other_queue);
	work_queue(work_queue<T>&& a_other_queue);
	work_queue<T>& operator=(work_queue<T>&& a_other_queue);
public:
	work_queue();
	virtual ~work_queue();
	void add_work_item(T a_item);
	std::size_t queue_size();
	std::optional<T> wait_for_item(std::size_t a_ms);
	void shut_down();
	bool is_shut_down();
	bool wait_for_empty(std::size_t a_ms);
	
protected:
	std::deque<T> m_queue;
	std::mutex m_queue_mutex;
	std::mutex m_cond_mutex;
	std::condition_variable m_cond;
	std::atomic<bool> m_shut_down;
};

template <typename T>
work_queue<T>::work_queue()
: m_shut_down(false)
{
}

template <typename T>
work_queue<T>::~work_queue()
{
}

template <typename T>
void work_queue<T>::shut_down()
{
	m_shut_down = true;
}

template <typename T>
bool work_queue<T>::is_shut_down()
{
	return m_shut_down;
}

template <typename T>
void work_queue<T>::add_work_item(T a_item)
{
	std::lock_guard<std::mutex> l_guard(m_queue_mutex);
	m_queue.push_back(a_item);
	m_cond.notify_one();
}

template <typename T>
std::size_t work_queue<T>::queue_size()
{
	std::lock_guard<std::mutex> l_guard(m_queue_mutex);
	return m_queue.size();
}

template <typename T>
std::optional<T> work_queue<T>::wait_for_item(std::size_t a_ms)
{
	T ret;
	m_queue_mutex.lock();
	if (m_queue.size() == 0) {
		m_queue_mutex.unlock();
		// block on condition until we are signalled
		std::unique_lock l_ul(m_cond_mutex);
		if (a_ms == 0) {
			m_cond.wait(l_ul);
		} else {
			if (m_cond.wait_for(l_ul, std::chrono::milliseconds(a_ms)) == std::cv_status::timeout) {
				l_ul.unlock();
				return std::nullopt;
			}
		}
		l_ul.unlock();
		m_queue_mutex.lock(); // lock again when we wake up
	}
	// queue contains items, or we woke up
	// check to make sure queue actually has an item
	if (m_queue.size() == 0) {
		m_queue_mutex.unlock();
		return std::nullopt;
	}
	ret = m_queue.front();
	m_queue.pop_front();
	m_queue_mutex.unlock();
	return ret;
}

template <typename T>
bool work_queue<T>::wait_for_empty(std::size_t a_ms)
{
	m_queue_mutex.lock();
	if (m_queue.size() == 0) {
		// empty!
		m_queue_mutex.unlock();
		return true;
	} else {
		// periodically check every 10ms until maximum wait period (a_ms) has been reached
		m_queue_mutex.unlock();
		while (a_ms > 0) {
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
			a_ms -= 10;
			m_queue_mutex.lock();
			if (m_queue.size() == 0) {
				m_queue_mutex.unlock();
				return true;
			}
			m_queue_mutex.unlock();
		}
		// no joy, we reached our timeout period and the queue still has items
		m_queue_mutex.unlock();
		return false;
	}
}

// work_queue_thread

template <typename T>
class work_queue_thread : public ss::ccl::thread {
public:
	work_queue_thread(const std::string& a_logname, ss::ccl::work_queue<T>& a_queue);
	work_queue_thread(const work_queue_thread& a_thread) = delete;
	work_queue_thread(work_queue_thread&& a_thread) = delete;
	virtual void execute();
	virtual void dispatch(T a_work_item) = 0;
protected:
	work_queue<T>& m_queue;
};

template <typename T>
work_queue_thread<T>::work_queue_thread(const std::string& a_logname, ss::ccl::work_queue<T>& a_queue)
: ss::ccl::thread(a_logname)
, m_queue(a_queue)
{
}

template <typename T>
void work_queue_thread<T>::execute()
{
	while (!m_queue.is_shut_down()) {
		std::optional<T> l_item = m_queue.wait_for_item(20);
		if (l_item.has_value()) {
			dispatch(l_item.value());
		}
	}
}

} // namespace ccl
} // namespace ss

#endif //CCL_H

