/*
    HTTPS with connection control
	!! ports are still vulnerable !!

	~ Comments, code was made by LeomJson (leo)
	HTTPS Credibility: https://github.com/yhirose/cpp-httplib
*/
#include "httplib.h"
#include "json.hpp"
#include <future>
httplib::SSLServer server("cert.pem", "key.pem");
using namespace std;
using req = httplib::Request;
using res = httplib::Response;
vector<thread> backtasks;

// This prevents DDoS- sense your rejecting "disrup", but as commented above this only prevents mild disruptions and WONT protect firewall ports.
#define r_seconds 4 // second(s)
#define requests 3 // allowing "requests" per "seconds" else reject connection.

const char* server_data =
R"(server|127.0.0.1
port|55231
type|1
meta|cmeta
RTENDMARKERBS1001)";
const char* gov = R"(<style>h1 {
text-align: center;
} 
</style> 
<body>
<h1><b><big>Unauthorized Access</big></b></h1>
</body>)";
class connection
{
public:
	string ip = "";
	int attempts = 0; // this will act as the HTTPS stressor
	bool timeout = false;
	bool new_connection = false;
};
map<string, connection> connection_data;
void SaveConnectionData(connection data, string ip) {
	ofstream w("https/connection/" + ip);
	nlohmann::json j; j.dump(1);
	j["ip"] = data.ip;
	j["attempts"] = data.attempts;
	j["timeout"] = data.timeout;
	w << setw(2) << j;
}
connection LoadConnectionData(string ip) {
	ifstream r("https/connection/" + ip);
	nlohmann::json j; r >> j;
	connection data;
	data.ip = j["ip"];
	data.attempts = j["attempts"];
	data.timeout = j["timeout"];
	return data; // return the data for using the connection object elsewhere
}
void append_reset(string ip) {
	while (true) {
		for (auto it = connection_data.begin(); it != connection_data.end(); ++it) {
			if (it->first == ip) {
				if (it->second.timeout == true) {
					this_thread::sleep_for(chrono::seconds(r_seconds));
					it->second.timeout = false, it->second.attempts -= requests;
					connection data = LoadConnectionData(ip);
					data.timeout = it->second.timeout, data.attempts = it->second.attempts;
					SaveConnectionData(data, it->second.ip);
				}
			}
		}
		this_thread::sleep_for(1ms);
	}
}
bool request(const req req, res res)
{
	ifstream r("https/connection/" + req.remote_addr);
	if (not r.is_open()) {
		connection new_data;
		new_data.ip = req.remote_addr;
		new_data.attempts = 1;
		new_data.new_connection = false;
		SaveConnectionData(new_data, req.remote_addr);
		connection_data.emplace(req.remote_addr, new_data);
	}
	else {
		for (auto it = connection_data.begin(); it != connection_data.end(); ++it) {
			if (it->first == req.remote_addr) {
				it->second.attempts++;
				if (it->second.attempts > requests) {
					it->second.timeout = true;
					backtasks.emplace_back(append_reset, req.remote_addr);
					return false;
				}
				connection data = LoadConnectionData(req.remote_addr);
				data.attempts = it->second.attempts;
				data.timeout = it->second.timeout;
				SaveConnectionData(data, it->second.ip);
			}
		}
	}
	return true;
}
int main()
{
	server.Post(("/growtopia/server_data.php"), [&](const req& req, res& res) {
		future<bool> Request = async(request, req, res); Request.wait();
	if (not Request.get()) return;
	res.set_content(server_data, "text/plain");
		});
	server.Get(("/growtopia/server_data.php"), [&](const req& req, res& res) {
		res.set_content(gov, "text/html");
		});
	server.listen("0.0.0.0", 443);
	while (server.is_running());
	backtasks.clear();
	server.stop();
	return 0; // program ends
}