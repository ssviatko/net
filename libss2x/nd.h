#ifndef ND_H
#define ND_H

#include <string>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <optional>
#include <map>
#include <tuple>
#include <memory>
#include <algorithm>

#include "log.h"
#include "data.h"
#include "doubletime.h"
#include "ccl.h"
#include "dispatchable.h"

namespace ss {
namespace ccl {

// note attributes

class note_attributes {
public:
	note_attributes() {}
	~note_attributes() {}
	std::size_t size() const { return m_attribdb.size(); }
	void set_keyvalue(const std::string& a_key, const std::string& a_value);
	std::string keyvalue(const std::string& a_key);
	std::map<std::string, std::string>& keymap() { return m_attribdb; }
	
protected:
	std::map<std::string, std::string> m_attribdb;
};

const note_attributes empty_attributes = ss::ccl::note_attributes();

// note class

class note {
	void copy_construct(const note& a_other_note);
	
public:
	typedef std::function<void(std::shared_ptr<ss::ccl::note>)> cb_t;

	// standard note names
	constexpr const static std::string SYS_DEFAULT = "SYS_DEFAULT";
	constexpr const static std::string SYS_ALTERNATE = "SYS_ALTERNATE";
	constexpr const static std::string SYS_SPECIAL = "SYS_SPECIAL";
	constexpr const static std::string SYS_REQUEST = "SYS_REQUEST";
	
	// standard replies
	constexpr const static std::string REPLY_OK = "REPLY_OK";
	constexpr const static std::string REPLY_CANCEL = "REPLY_CANCEL";
	constexpr const static std::string REPLY_ERROR = "REPLY_ERROR";
	
	// constructors
	note();
	note(const note& a_note);
	note(note&& a_note);
	note(const std::string& a_note_name);
	virtual ~note();
	
	// assignment
	note& operator=(const note& a_other_note);
	note& operator=(note&& a_other_note);

	// data access
	std::string name() const { return m_note_name; };
	std::string guid() const { return m_guid.as_hex_str_nospace(); }
	void set_delivered() { m_delivered = true; m_delivered_cond.notify_all(); }
	void set_seen() { m_seen = true; m_seen_cond.notify_all(); }
	void set_reply_requested() { m_reply_requested = true; }
	void set_replied() { m_replied = true; m_replied_cond.notify_all(); }
	void set_reply(const std::string& a_reply);
	void set_attributes(const note_attributes& a_attrib);
	
	bool delivered() const { return m_delivered; }
	bool seen() const { return m_seen; }
	bool reply_requested() const { return m_reply_requested; }
	bool replied() const { return m_replied; }
	std::string reply();
	note_attributes attributes();
	
	bool wait_for_delivered(std::size_t a_timeout_ms);
	bool wait_for_seen(std::size_t a_timeout_ms);
	bool wait_for_replied(std::size_t a_timeout_ms);
	
protected:
	std::string m_note_name;
	std::string m_reply_name;
	std::mutex m_reply_name_mutex;
	data m_guid;
	std::atomic<bool> m_delivered;
	std::mutex m_delivered_mutex;
	std::condition_variable m_delivered_cond;
	std::atomic<bool> m_seen;
	std::mutex m_seen_mutex;
	std::condition_variable m_seen_cond;
	std::atomic<bool> m_reply_requested;
	std::atomic<bool> m_replied;
	std::mutex m_replied_mutex;
	std::condition_variable m_replied_cond;
	note_attributes m_attributes;
	std::mutex m_attributes_mutex;
};

// nd agent
 
class nd_agent : public ss::ccl::work_queue_thread<std::tuple<ss::ccl::note::cb_t, std::shared_ptr<ss::ccl::note> > > {	
public:
	nd_agent(const std::string& a_logname, ss::ccl::work_queue<std::tuple<ss::ccl::note::cb_t, std::shared_ptr<ss::ccl::note> > >& a_queue)
		: ss::ccl::work_queue_thread<std::tuple<ss::ccl::note::cb_t, std::shared_ptr<ss::ccl::note> > >(a_logname, a_queue) { }
	~nd_agent() { }
	nd_agent(const nd_agent& a_agent) = delete;
	nd_agent(nd_agent&& a_agent) = delete;
	void dispatch(std::tuple<ss::ccl::note::cb_t, std::shared_ptr<ss::ccl::note> > a_work_item);
};

// nd (note dispatcher)

class nd : public ss::ccl::dispatchable {
	// singleton pattern - constructors are hidden
	nd();
	~nd() { }
	virtual void starting();
	virtual void started();
	virtual void halting();
	virtual void halted();
	virtual bool dispatch();
	
	const std::size_t AGENTS = 8;
	
public:
	static nd& get();
	void shutdown();
	
	std::shared_ptr<ss::ccl::note> post(const std::string& a_note_name, bool a_reply, ss::ccl::note_attributes a_attributes = ss::ccl::empty_attributes);
	void add_listener(const std::string& a_note_name, ss::ccl::note::cb_t a_cb);
	void remove_listeners_for_note(const std::string& a_note_name);
	void remove_all_listeners();
	
protected:
	ss::ccl::work_queue<std::shared_ptr<ss::ccl::note> > m_post_queue;
	ss::ccl::work_queue<std::tuple<ss::ccl::note::cb_t, std::shared_ptr<ss::ccl::note> > > m_call_queue;
	std::vector<std::shared_ptr<nd_agent> > m_agents;
	std::multimap<std::string, ss::ccl::note::cb_t> m_callbacks;
	std::mutex m_callbacks_mutex;
};

} // namespace ccl
} // namespace ss

#endif //ND_H

