#include "fortune_server.h"

fortune_server::fortune_server()
: ss::net::command_server("fortune_server", "fortune_auth_db.json")
{
	ctx.log("fortune_server starting up..");
	ctx.log("fortune_server UP");
}

fortune_server::~fortune_server()
{
	
}

void fortune_server::shutdown()
{
	ctx.log("Shutting down fortune_server subsystem..");
	ctx.log("fortune_server DOWN");
	command_server::shutdown();
}

void fortune_server::external_command(int client_sockfd, std::vector<std::string>& a_cmdv)
{
	if (a_cmdv[0] == "FORTUNE") {
		send_to_client(client_sockfd, "You will move mountains.. in bed.");
	} else {
		send_to_client(client_sockfd, "fortune_server: unrecognized command.");
	}
}