#include "request_data.hpp"
#include "httplib.h"
httplib::SSLServer server("cert.pem", "key.pem");
using namespace std;
using req = httplib::Request;
using res = httplib::Response;

bool main()
{
	server.Post(("/growtopia/server_data.php"), [&](const req& req, res& res) {
		res.set_content(server_data, "text/plain");
		});
	server.Get(("/growtopia/server_data.php"), [&](const req& req, res& res) { 
		res.set_content(gov, "text/html");
		});
	server.Get(("/"), [&](const req& req, res& res) {
		res.set_content(gov, "text/html");
		});
	server.listen("0.0.0.0", 443);
	while (true);
	return true;
}