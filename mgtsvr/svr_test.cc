#include <iostream>
#include <thread>
#include <chrono>

#include "log.h"
#include "fs.h"
#include "fortune_server.h"

int main(int argc, char **argv)
{
	ss::failure_services& l_fs = ss::failure_services::get();
	ss::log::ctx& ctx = ss::log::ctx::get();
	ctx.register_thread("main");
	std::shared_ptr<ss::log::target_stdout> l_stdout =
		std::make_shared<ss::log::target_stdout>(ss::log::DEBUG, ss::log::target_stdout::DEFAULT_FORMATTER_DEBUGINFO);
	ctx.add_target(l_stdout, "default");
	ss::icr& l_icr = ss::icr::get();
	l_icr.read_file("fortune.ini", false);
	l_icr.read_arguments(argc, argv);

	ss::net::fortune_server l_server;
	
	// create default user
	bool l_add_user_success = l_server.add_user_plaintext_pw("ssviatko", "banana");
	ctx.log(std::format("add default user ssviatko: {}", l_add_user_success));

	auto ctrlc = [&]() {
		ctx.log_p(ss::log::NOTICE, "Ctrl-C Pressed, exiting gracefully...");
		l_server.shutdown();
		exit(EXIT_SUCCESS);
	};
	
	l_fs.install_signal_handler();
	l_fs.install_sigint_handler(ctrlc);
	
	while (1)
		std::this_thread::sleep_for(std::chrono::microseconds(50));
	
	return 0;
}
