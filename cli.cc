#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <deque>
#include <thread>
#include <mutex>
#include <cstdint>
#include <semaphore>
#include <optional>

#include <signal.h>
#include <fcntl.h>
#include <ncurses.h>
#include <unistd.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <string.h>
#include <errno.h>

#include "data.h"
#include "doubletime.h"
#include "icr.h"

enum conn_type {
	CONN_NONE,
	CONN_TCP,
	CONN_UNIX
} g_conn;

enum keypress_state {
	// our keypress stat machine in our main loop
	KPS_NONE,
	KPS_COLLECT,
	KPS_HISTORY,
	KPS_SCROLLBACK
} g_state;

enum content_msgtype {
	// determines what color the content message is
	CMT_NONE, // boring gray
	CMT_COMMAND, // electric hi-viz cyan
	CMT_SYSTEM // psychedelic magenta
};

// socket client
int epoll_fd;
int client_fd;
ss::data g_in_circbuff;
ss::data g_out_circbuff;
std::mutex g_out_circbuff_mtx;

// dispatch thread
bool iodispatch_running = false;
std::binary_semaphore iodispatchthr_started { 0 };
std::binary_semaphore iodispatchthr_stopped { 0 };

bool g_run = true;

// UI
int g_row, g_col; // size of stdscr
WINDOW *g_input = nullptr;
int g_input_height = 3;
const int g_input_height_default = 3;
WINDOW *g_pad = nullptr;
int g_pad_height, g_pad_width; // set in INI file; size of entire virtual screen
int g_pad_cur_row, g_pad_cur_col; // current cursor location inside of pad
int g_padwin_origin_row = 0; // upper left coordinate of screen to display pad
int g_padwin_origin_col = 0;
int g_padwin_height; // size in character cells of pad window (computed based on g_row/g_col and input size)
int g_padwin_width;
int g_scrollback_max = 0;
int g_scrollback_cur = 0;
int g_scrollback_max_tab = 0;
int g_scrollback_cur_tab = 0;

// command history buffering
std::deque<std::string> g_history_buffer;
std::uint64_t g_history_buffer_scrollback;
std::uint64_t g_history_buffer_current;
bool g_history_is_persistent; // should we load/save our history?
std::string g_history_cache; // history cache file

// client log file
std::ofstream g_log_file;
std::string g_log_filename;

// input line
std::string g_input_line;
int g_insert_point = 0;

void refresh_pad()
{
	getyx(g_pad, g_pad_cur_row, g_pad_cur_col);
	int top_display_row = 0; // top display row inside of pad to display
	// if our pad has scrolled off the screen, move top_display_row down accordingly
	if (g_pad_cur_row >= g_padwin_height)
		top_display_row = g_pad_cur_row - g_padwin_height;
	prefresh(g_pad, top_display_row, 0, g_padwin_origin_row, g_padwin_origin_col, g_padwin_origin_row + g_padwin_height, g_padwin_origin_col + g_padwin_width);
}

void refresh_scrollback()
{
	prefresh(g_pad, g_scrollback_cur, g_scrollback_cur_tab, g_padwin_origin_row, g_padwin_origin_col, g_padwin_origin_row + g_padwin_height, g_padwin_origin_col + g_padwin_width);
}

void enter_scrollback()
{
	getyx(g_pad, g_pad_cur_row, g_pad_cur_col);
	if (g_pad_cur_row >= g_padwin_height)
		g_scrollback_max = g_pad_cur_row - g_padwin_height;
	g_scrollback_cur = g_scrollback_max;
	g_scrollback_max_tab = g_pad_width - g_padwin_width;
	g_scrollback_cur_tab = 0;
	refresh_scrollback();
}

void leave_scrollback()
{
	refresh_pad();
}

void graceful_exit()
{
	g_run = false;
}

void init_windows()
{
	keypad(stdscr, TRUE);
	refresh();
	getmaxyx(stdscr, g_row, g_col);
	g_padwin_width = g_col - 1;
	g_padwin_height = g_row - g_input_height - 1;
	if (g_input != nullptr)
		delwin(g_input);
	g_input = newwin(g_input_height - 1, g_col, g_row - g_input_height + 1, 0);
	scrollok(g_input, TRUE);
	keypad(g_input, TRUE);
	werase(stdscr);
	werase(g_input);
	wmove(stdscr, g_row - g_input_height, 0);
	attron(COLOR_PAIR(1));
	attron(A_BOLD);
	whline(stdscr, ACS_HLINE, g_col);
	attroff(A_BOLD);
	attroff(COLOR_PAIR(1));
	refresh();
	refresh_pad();
}

void refresh_input_line()
{
	int l_input_line_height = (g_input_line.size() / g_col) + 1;
	if (l_input_line_height > (g_input_height - 1)) {
		g_input_height = l_input_line_height + 1;
		init_windows();
	}
	werase(g_input);
	wmove(g_input, 0, 0);
	wattron(g_input, COLOR_PAIR(1));
	wattron(g_input, A_BOLD);
	if (g_state == keypress_state::KPS_SCROLLBACK) {
		std::string l_sbhelp = "SCROLLBACK: arrows move, pgup/pgdn, home/end, F8 to exit";
		if ((unsigned int)g_col > l_sbhelp.size() + 6) {
			wmove(g_input, 0, (g_col / 2) - (l_sbhelp.size() / 2));
			wprintw(g_input, "%s", l_sbhelp.c_str());
		}
		wmove(g_input, 0, 0);
		wprintw(g_input, ">> ");
		wmove(g_input, 0, g_col - 3);
		wprintw(g_input, " <<");
	} else {
		wprintw(g_input, "%s", g_input_line.c_str());
		// make fake "cursor" at insert point
		int l_invcol, l_invrow; // col/row to inverse in g_input window
		l_invcol = g_insert_point % g_col;
		l_invrow = g_insert_point / g_col;
		wmove(g_input, l_invrow, l_invcol);
		wchgat(g_input, 1, A_REVERSE, 1, NULL);
	}
	wattroff(g_input, A_BOLD);
	wattroff(g_input, COLOR_PAIR(1));
	wrefresh(g_input);
}

void resize_window()
{
	endwin();
	refresh();
	init_windows();
	refresh_input_line();
}

void display_to_content(content_msgtype a_type, const std::string& a_string)
{
	if (a_type == content_msgtype::CMT_COMMAND) {
		wattron(g_pad, COLOR_PAIR(1));
		wattron(g_pad, A_BOLD);
		wprintw(g_pad, "%s\n", a_string.c_str());
		wattroff(g_pad, A_BOLD);
		wattroff(g_pad, COLOR_PAIR(1));
	} else if (a_type == content_msgtype::CMT_SYSTEM) {
		wattron(g_pad, COLOR_PAIR(2));
		wattron(g_pad, A_BOLD);
		wprintw(g_pad, "%s\n", a_string.c_str());
		wattroff(g_pad, A_BOLD);
		wattroff(g_pad, COLOR_PAIR(2));
	} else {
		wprintw(g_pad, "%s\n", a_string.c_str());
	}
	refresh_pad();
	if (g_log_file.is_open()) {
		g_log_file << a_string << std::endl;
		g_log_file.flush();
	}
}

void handle_signal(int signo)
{
	switch (signo) {
		case SIGINT:
//			wprintw(g_content, "caught SIGINT, gracefully exiting...\n");
			graceful_exit();
			break;
		case SIGWINCH:
			resize_window();
			break;
		default:
			std::cerr << "caught unexpected signal, exiting!" << std::endl;
			exit(EXIT_FAILURE);
			break;
	}
}

void connect_socket()
{
	ss::icr& l_icr = ss::icr::get();
	switch (g_conn) {
		case conn_type::CONN_NONE:
			// nothing to do
			display_to_content(content_msgtype::CMT_SYSTEM, "No connection type selected.");
			break;
		case conn_type::CONN_TCP:
		{
			if (!l_icr.key_is_defined("client", "port")) {
				throw std::runtime_error("key <port> must be defined under category [client], exiting.");
			}
			if (!l_icr.key_is_defined("client", "ip")) {
				throw std::runtime_error("key <ip> must be defined under category [client], exiting.");
			}
			std::stringstream l_ss;
			l_ss << "TCP connection selected: " << l_icr.keyvalue("client", "ip") << ":" << l_icr.keyvalue("client", "port");
			display_to_content(content_msgtype::CMT_SYSTEM, l_ss.str());
			
			client_fd = socket(AF_INET, SOCK_STREAM, 0);
			if (client_fd == -1) {
				throw std::runtime_error("client: socket() call failed, exiting!");
			}

			// add client socket to epoll
			struct epoll_event ev;
			ev.events = EPOLLIN | EPOLLRDHUP;
			ev.data.fd = client_fd;
			if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) == -1) {
				throw std::runtime_error("client: unable to add client socket to epoll, exiting!");
			}

			// name the socket
			struct sockaddr_in l_address;
			std::uint16_t l_listen_port = l_icr.to_integer(l_icr.keyvalue("client", "port"));
			l_address.sin_family = AF_INET;
			l_address.sin_addr.s_addr = inet_addr(l_icr.keyvalue("client", "ip").c_str());
			l_address.sin_port = htons(l_listen_port);
			int client_len = sizeof(l_address);
			
			// connect
			int conn_res = connect(client_fd, (struct sockaddr *)&l_address, client_len);
			if (conn_res < 0) {
				// politely tell the user what is wrong
				display_to_content(content_msgtype::CMT_SYSTEM, "Unable to connect to server.");
				std::stringstream l_ss;
				l_ss << "errno: " << errno << " " << strerror(errno);
				display_to_content(content_msgtype::CMT_SYSTEM, l_ss.str());
				close(client_fd);
				break;
			}

			// make client socket nonblocking
			int client_sockfd_flags = fcntl(client_fd, F_GETFL);
			client_sockfd_flags |= O_NONBLOCK;
			if (fcntl(client_fd, F_SETFL, client_sockfd_flags) == -1) {
				throw std::runtime_error("client: unable to set client_sockfd_flags, exiting!");
			}
			display_to_content(content_msgtype::CMT_SYSTEM, "Successfully connected to server!");
		}
			break;
		case conn_type::CONN_UNIX:
		{
			if (!l_icr.key_is_defined("client", "unix_socket")) {
				throw std::runtime_error("key <unix_socket> must be defined under category [client], exiting.");
			}
			std::stringstream l_ss;
			l_ss << "UNIX socket connection selected: " << l_icr.keyvalue("client", "unix_socket");
			display_to_content(content_msgtype::CMT_SYSTEM, l_ss.str());
			
			client_fd = socket(AF_UNIX, SOCK_STREAM, 0);
			if (client_fd == -1) {
				throw std::runtime_error("client: socket() call failed, exiting!");
			}

			// add client socket to epoll
			struct epoll_event ev;
			ev.events = EPOLLIN | EPOLLRDHUP;
			ev.data.fd = client_fd;
			if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) == -1) {
				throw std::runtime_error("client: unable to add client socket to epoll, exiting!");
			}
			
			// name the socket
			struct sockaddr_un l_address;
			l_address.sun_family = AF_UNIX;
			std::string l_sockname = l_icr.keyvalue("client", "unix_socket");
			strcpy(l_address.sun_path, l_sockname.c_str());
			int client_len = sizeof(l_address);
			
			// connect
			int conn_res = connect(client_fd, (struct sockaddr *)&l_address, client_len);
			if (conn_res < 0) {
				// politely tell the user what is wrong
				display_to_content(content_msgtype::CMT_SYSTEM, "Unable to connect to server.");
				std::stringstream l_ss;
				l_ss << "errno: " << errno << " " << strerror(errno);
				display_to_content(content_msgtype::CMT_SYSTEM, l_ss.str());
				close(client_fd);
				break;
			}

			// make client socket nonblocking
			int client_sockfd_flags = fcntl(client_fd, F_GETFL);
			client_sockfd_flags |= O_NONBLOCK;
			if (fcntl(client_fd, F_SETFL, client_sockfd_flags) == -1) {
				throw std::runtime_error("client: unable to set client_sockfd_flags, exiting!");
			}
			display_to_content(content_msgtype::CMT_SYSTEM, "Successfully connected to server!");
		}
			break;
	}
}

void execute_command(const std::string& a_string)
{
	// check if new command is different from front of history buffer before adding it
	if (g_history_buffer.size() > 0) {
		if (a_string != g_history_buffer[0]) {
			g_history_buffer.push_front(a_string);
			if (g_history_buffer.size() > g_history_buffer_scrollback)
				g_history_buffer.pop_back();
		}
	} else {
		// nothing in history buffer so add this first item
		g_history_buffer.push_front(a_string);
	}
	// display this command in the content
	display_to_content(content_msgtype::CMT_COMMAND, a_string);
	// insert this command into socket output buffer
	g_out_circbuff_mtx.lock();
	g_out_circbuff.write_std_str_delim(a_string);
	g_out_circbuff_mtx.unlock();
	struct epoll_event l_client_info;
	l_client_info.events = EPOLLIN | EPOLLHUP | EPOLLOUT;
	l_client_info.data.fd = client_fd;
	epoll_ctl(epoll_fd, EPOLL_CTL_MOD, client_fd, &l_client_info);
}

void iodispatch()
{
	iodispatchthr_started.release();
	int l_max_events = 500;
	struct epoll_event events[l_max_events];
	while (iodispatch_running) {
		int n = epoll_wait(epoll_fd, events, l_max_events, 10);
		if (n == 0) {
			// no events, grab strings from input buffer and post to console
			std::optional<std::string> l_instr;
			do {
				l_instr = g_in_circbuff.read_std_str_delim();
				if (l_instr.has_value()) {
					display_to_content(content_msgtype::CMT_NONE, l_instr.value());
				}
			} while (l_instr.has_value());
			continue;
		}
		while (n-- > 0) {
			if (events[n].events & EPOLLIN) {
				std::uint8_t buff[16384];
				int readbytes = read(client_fd, buff, 16384);
				if (readbytes <= 0) {
					// EOF
					iodispatch_running = false;
					goto hangup;
				} else {
					// stick the data in client's input circular buffer
					g_in_circbuff.assign(buff, readbytes);
				}
			} else if (events[n].events & EPOLLHUP) {
				iodispatch_running = false;
				goto hangup;
			} else if (events[n].events & EPOLLOUT) {
				g_out_circbuff_mtx.lock();
				std::size_t l_datalen = g_out_circbuff.size();
				// write in chunks
				int l_towrite = (l_datalen > 4096) ? 4096 : l_datalen;
				int l_ret = write(client_fd, g_out_circbuff.buffer(), l_towrite);
				if (l_ret < 0) {
					// error
				} else if (l_ret == 0) {
					// EOF
				} else if (l_ret < l_towrite) {
					// partial write... (why?)
					std::stringstream l_ss;
					l_ss << "wrote " << l_ret << " bytes, expected " << l_towrite << std::endl;
				} else if (l_ret == l_towrite) {
					// all bytes written
				}

				g_out_circbuff.truncate_front(l_ret);

				if (g_out_circbuff.size() == 0) {
					// we emptied it, so clear EPOLLOUT flag for fd
					struct epoll_event l_client_info;
					l_client_info.events = EPOLLIN | EPOLLHUP;
					l_client_info.data.fd = client_fd;
					epoll_ctl(epoll_fd, EPOLL_CTL_MOD, client_fd, &l_client_info);
				}
				g_out_circbuff_mtx.unlock();
			}
		}
	}
hangup:
	display_to_content(content_msgtype::CMT_SYSTEM, "Server hung up on us! Connection terminated. Press (ctrl-C) to exit.");
	close(client_fd);

	iodispatchthr_stopped.release();
}

int main(int argc, char **argv)
{
	// set circular buffers to circular mode
	g_in_circbuff.set_circular_mode(true);
	g_out_circbuff.set_circular_mode(true);

	// make sure the cli.ini file exists
	struct stat l_thumbstat;
	if (stat("cli.ini", &l_thumbstat) < 0) {
		std::cerr << "error: cli.ini file missing or damaged." << std::endl;
		exit(EXIT_FAILURE);
	}
	
	// init icr
	ss::icr& l_icr = ss::icr::get();
	l_icr.read_file("cli.ini", false);
	l_icr.read_arguments(argc, argv);
	
	// catch signals
	struct sigaction sa;
	sa.sa_handler = handle_signal;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGINT);
	sigaddset(&sa.sa_mask, SIGWINCH);
	sa.sa_flags = 0;
	if (sigaction(SIGINT, &sa, NULL) < 0) {
		std::cerr << "unable to catch SIGINT, exiting!" << std::endl;
		exit(EXIT_FAILURE);
	}
	if (sigaction(SIGWINCH, &sa, NULL) < 0) {
		std::cerr << "unable to catch SIGWINCH, exiting!" << std::endl;
		exit(EXIT_FAILURE);
	}
	
	// init epoll
	if ((epoll_fd = epoll_create1(EPOLL_CLOEXEC)) == -1) {
		throw std::runtime_error("client: unable to initialize epoll, exiting!");
	}
	
	// determine our connection type and init socket accordingly
	if (!l_icr.key_is_defined("client", "connection")) {
		throw std::runtime_error("key <connection> must be defined under category [client], exiting.");
	}
	if (!l_icr.key_is_defined("client", "scrollback")) {
		throw std::runtime_error("key <scrollback> must be defined under category [client], exiting.");
	}
	g_pad_height = l_icr.to_integer(l_icr.keyvalue("client", "scrollback"));
	if (!l_icr.key_is_defined("client", "pad_width")) {
		throw std::runtime_error("key <pad_width> must be defined under category [client], exiting.");
	}
	g_pad_width = l_icr.to_integer(l_icr.keyvalue("client", "pad_width"));
	if (!l_icr.key_is_defined("client", "history")) {
		throw std::runtime_error("key <history> must be defined under category [client], exiting.");
	}
	if (!l_icr.key_is_defined("client", "history_is_persistent")) {
		throw std::runtime_error("key <history_is_persistent> must be defined under category [client], exiting.");
	}
	if (!l_icr.key_is_defined("client", "history_cache")) {
		throw std::runtime_error("key <history_cache> must be defined under category [client], exiting.");
	}
	g_history_buffer_scrollback = l_icr.to_integer(l_icr.keyvalue("client", "history"));
	g_history_is_persistent = l_icr.to_boolean(l_icr.keyvalue("client", "history_is_persistent"));
	g_history_cache = l_icr.keyvalue("client", "history_cache");
	
	if (!l_icr.key_is_defined("client", "log")) {
		throw std::runtime_error("key <log> must be defined under category [client], exiting.");
	}
	g_log_filename = l_icr.keyvalue("client", "log");
	
	g_conn = conn_type::CONN_NONE;
	if (l_icr.keyvalue("client", "connection") == "tcp") {
		g_conn = conn_type::CONN_TCP;
	}
	if (l_icr.keyvalue("client", "connection") == "unix") {
		g_conn = conn_type::CONN_UNIX;
	}
	
	// init ncurses
	initscr();
	cbreak();
	noecho();
	curs_set(0);
	start_color();
	init_pair(1, COLOR_CYAN, COLOR_BLACK);
	init_pair(2, COLOR_MAGENTA, COLOR_BLACK);
	g_pad = newpad(g_pad_height, g_pad_width);
	scrollok(g_pad, TRUE);
	keypad(g_pad, TRUE);
	init_windows();
	
	// open screen log
	g_log_file.open(g_log_filename.c_str(), std::ios::ate | std::ios::app);
	if (!g_log_file.is_open()) {
		display_to_content(content_msgtype::CMT_SYSTEM, "Having difficulty opening screen log file, please check cli.ini.");
	} else {
		// print session separator to log file
		g_log_file << std::endl << "  >>> NEW SESSION at: " << ss::doubletime::now_as_iso8601_us() << std::endl << std::endl;
		g_log_file.flush();
	}

	std::stringstream l_banner;
	l_banner << "Stream Socket Client - release " << RELEASE_NUMBER << " build " << BUILD_NUMBER;
	display_to_content(content_msgtype::CMT_SYSTEM, l_banner.str());

	// load history?
	if (g_history_is_persistent) {
		std::ifstream l_history;
		std::string l_instr;
		l_history.open(g_history_cache.c_str(), std::ios::in);
		if (!l_history.is_open()) {
			display_to_content(content_msgtype::CMT_SYSTEM, "History cache missing or damaged, will attempt to create new history cache file on program exit.");
		} else {
			while (std::getline(l_history, l_instr)) {
				g_history_buffer.push_back(l_instr);
				// make sure we don't overrun our set history size
				if (g_history_buffer.size() > g_history_buffer_scrollback)
					g_history_buffer.pop_back();
			}
		}
	}
	
	connect_socket();

	// start iodispatch thread
	iodispatch_running = true;
	std::thread l_dispatch_thr(&iodispatch);
	iodispatchthr_started.acquire();
	l_dispatch_thr.detach();

	// handle i/o in special dispatch thread, watch the keyboard here for input.
	int l_char;
	g_input_line = "";
	g_insert_point = 0;
	refresh_input_line();

	display_to_content(content_msgtype::CMT_SYSTEM, "Press (ctrl-C) to exit.");

	// state machine: move back and forth between collecting keystrokes,
	// scrolling through recent command history, or viewing scrollback.
	g_state = keypress_state::KPS_COLLECT;
		
	while (g_run) {
		
		l_char = getch();
		
		switch (g_state) {
			case keypress_state::KPS_NONE:
				break;
			case keypress_state::KPS_COLLECT:
			{
				do {
					if (l_char == KEY_LEFT) {
						if (g_insert_point > 0) {
							--g_insert_point;
							refresh_input_line();
						}
						break;
					}
					if (l_char == KEY_RIGHT) {
						if ((unsigned int)g_insert_point < g_input_line.size()) {
							++g_insert_point;
							refresh_input_line();
						}
						break;
					}
					if (l_char == KEY_UP) {
						// enter history mode from bottom of history list
						if (g_history_buffer.size() > 0) {
							g_history_buffer_current = 0;
							g_input_line = g_history_buffer[g_history_buffer_current];
							g_insert_point = g_input_line.size();
							refresh_input_line();
							g_state = keypress_state::KPS_HISTORY;
						}
						break;
					}
					if (l_char == KEY_DOWN) {
						// enter history mode from top of history list
						if (g_history_buffer.size() > 0) {
							g_history_buffer_current = g_history_buffer.size() - 1;
							g_input_line = g_history_buffer[g_history_buffer_current];
							g_insert_point = g_input_line.size();
							refresh_input_line();
							g_state = keypress_state::KPS_HISTORY;
						}
						break;
					}
					if (l_char == KEY_END) {
						if ((unsigned int)g_insert_point < g_input_line.size()) {
							g_insert_point = g_input_line.size();
							refresh_input_line();
						}
						break;
					}
					if (l_char == KEY_HOME) {
						g_insert_point = 0;
						refresh_input_line();
						break;
					}
					if (l_char == KEY_F(8)) {
//						display_to_content(content_msgtype::CMT_SYSTEM, "F8 key pressed (enter scrollback)");
						g_state = keypress_state::KPS_SCROLLBACK;
						refresh_input_line();
						enter_scrollback();
						break;
					}
					if (l_char == 27) {
						g_input_line = "";
						g_insert_point = 0;
						// check if we grew the input window
						if (g_input_height > g_input_height_default) {
							g_input_height = g_input_height_default;
							init_windows();
						}
						refresh_input_line();
						break;
					}
					if (l_char == 10) {
						std::string l_gotline = g_input_line;
						if (l_gotline.size() > 0) {
							g_input_line = "";
							g_insert_point = 0;
							// check if we grew the input window
							if (g_input_height > g_input_height_default) {
								g_input_height = g_input_height_default;
								init_windows();
							}
							execute_command(l_gotline);
							refresh_input_line();
						}
						break;
					}
					if (l_char == KEY_BACKSPACE) {
						if (g_insert_point > 0) {
							// delete character to left of cursor
							g_input_line.erase(g_insert_point - 1, 1);
							--g_insert_point;
							refresh_input_line();
						}
						break;
					}
					if (l_char == KEY_DC) {
						if ((unsigned int)g_insert_point < g_input_line.size()) {
							// delete character under the cursor
							g_input_line.erase(g_insert_point, 1);
							refresh_input_line();
						}
						break;
					}
					// after trapping all our special characters, ignore anything but alphanumerics/symbols
					// and add to input line
					if ((l_char >= 32) && (l_char <= 126)) {
						g_input_line.insert(g_insert_point, 1, l_char);
						++g_insert_point;
						refresh_input_line();
						break;
					}
				} while (0);
			}
				break;
			case keypress_state::KPS_HISTORY:
			{
				do {
					if (l_char == 27) {
						// clear the line and return to collect mode
						g_input_line = "";
						g_insert_point = 0;
						// check if we grew the input window
						if (g_input_height > g_input_height_default) {
							g_input_height = g_input_height_default;
							init_windows();
						}
						refresh_input_line();
						g_state = keypress_state::KPS_COLLECT;
						break;
					}
					if (l_char == KEY_UP) {
						if (g_history_buffer_current < (g_history_buffer.size() - 1)) {
							++g_history_buffer_current;
							g_input_line = g_history_buffer[g_history_buffer_current];
							g_insert_point = g_input_line.size();
							refresh_input_line();
						}
						break;
					}
					if (l_char == KEY_DOWN) {
						if (g_history_buffer_current > 0) {
							--g_history_buffer_current;
							g_input_line = g_history_buffer[g_history_buffer_current];
							g_insert_point = g_input_line.size();
							refresh_input_line();
						}
						break;
					}
					if (l_char == KEY_BACKSPACE) {
						// delete character to left of cursor
						g_input_line.erase(g_insert_point - 1, 1);
						--g_insert_point;
						refresh_input_line();
						g_state = keypress_state::KPS_COLLECT;
						break;
					}
					if (l_char == KEY_LEFT) {
						--g_insert_point;
						refresh_input_line();
						g_state = keypress_state::KPS_COLLECT;
						break;
					}
					if (l_char == 10) {
						std::string l_gotline = g_input_line;
						if (l_gotline.size() > 0) {
							g_input_line = "";
							g_insert_point = 0;
							// check if we grew the input window
							if (g_input_height > g_input_height_default) {
								g_input_height = g_input_height_default;
								init_windows();
							}
							execute_command(l_gotline);
							refresh_input_line();
							g_state = keypress_state::KPS_COLLECT;
						}
						break;
					}
					if ((l_char >= 32) && (l_char <= 126)) {
						g_input_line.insert(g_insert_point, 1, l_char);
						++g_insert_point;
						refresh_input_line();
						g_state = keypress_state::KPS_COLLECT;
						break;
					}
				} while (0);
			}
				break;
			case keypress_state::KPS_SCROLLBACK:
			{
				if (l_char == KEY_F(8)) {
					// return to collect mode
					g_state = keypress_state::KPS_COLLECT;
					refresh_input_line();
					leave_scrollback();
					break;
				}
				if (l_char == KEY_UP) {
					if (g_scrollback_cur > 0) {
						--g_scrollback_cur;
						refresh_scrollback();
					}
					break;
				}
				if (l_char == KEY_HOME) {
					if (g_scrollback_cur > 0) {
						g_scrollback_cur = 0;
						refresh_scrollback();
					}
					break;
				}
				if (l_char == KEY_PPAGE) {
					if (g_scrollback_cur > 0) {
						g_scrollback_cur -= (g_padwin_height - 1);
						if (g_scrollback_cur < 0)
							g_scrollback_cur = 0;
						refresh_scrollback();
					}
					break;
				}
				if (l_char == KEY_DOWN) {
					if (g_scrollback_cur < g_scrollback_max) {
						++g_scrollback_cur;
						refresh_scrollback();
					}
					break;
				}
				if (l_char == KEY_END) {
					if (g_scrollback_cur < g_scrollback_max) {
						g_scrollback_cur = g_scrollback_max;
						refresh_scrollback();
					}
					break;
				}
				if (l_char == KEY_NPAGE) {
					if (g_scrollback_cur < g_scrollback_max) {
						g_scrollback_cur += (g_padwin_height - 1);
						if (g_scrollback_cur > g_scrollback_max)
							g_scrollback_cur = g_scrollback_max;
						refresh_scrollback();
					}
					break;
				}
				if (l_char == KEY_RIGHT) {
					if (g_scrollback_cur_tab < g_scrollback_max_tab) {
						g_scrollback_cur_tab += 4;
						if (g_scrollback_cur_tab > g_scrollback_max_tab) {
							g_scrollback_cur_tab = g_scrollback_max_tab;
						}
						refresh_scrollback();
					}
					break;
				}
				if (l_char == KEY_LEFT) {
					if (g_scrollback_cur_tab > 0) {
						g_scrollback_cur_tab -= 4;
						if (g_scrollback_cur_tab < 0) {
							g_scrollback_cur_tab = 0;
						}
						refresh_scrollback();
					}
					break;
				}
			}
				break;
		}
	}
	
	// stop the iodispatch thread
	iodispatch_running = false;
	iodispatchthr_stopped.acquire();
	
	delwin(g_input);
	endwin();
	close(client_fd);
	if (g_log_file.is_open()) {
		g_log_file.flush();
		g_log_file.close();
	}
	
	// save history?
	if (g_history_is_persistent) {
		std::ofstream l_history;
		l_history.open(g_history_cache.c_str(), std::ios::trunc);
		if (!l_history.is_open()) {
			// display is gone by now, so just write to stderr
			std::cerr << "Unable to create/modify history cache file: " << g_history_cache << ", please check cli.ini and bridge directory." << std::endl;
		} else {
			for (auto& i : g_history_buffer) {
				l_history << i << std::endl;
			}
		}
	}
	
	return 0;
}

