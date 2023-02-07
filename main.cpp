#include "httplib.hpp"
#include "json.hpp"
#include <future>
#include <filesystem>
using namespace std;
httplib::SSLServer server("cert.pem", "key.pem");
vector<thread> backtasks;

#define r_seconds 2 // TODO: add backtask for resetting requests
#define requests 3

const char* server_data =
R"(server|127.0.0.1
port|17091
type|1
meta|cmeta
RTENDMARKERBS1001)";
const char* gov =
R"(<style>h1 { text-align: center; }
</style>
<body>
<h1><b><big>Unauthorized Access</big></b></h1>
</body>)";
class connection {
public:
	string ip = "";
	int attempts = 0;
};
map<string, connection> connection_data;
void SaveConnectionData(connection data, string ip) {
	ofstream w("connection/" + ip);
	nlohmann::json j; j.dump(1);
	j["ip"] = data.ip;
	j["attempts"] = data.attempts;
	w << setw(2) << j;
}
connection LoadConnectionData(string ip) {
	ifstream r("connection/" + ip);
	nlohmann::json j; r >> j;
	connection data;
	data.ip = j["ip"];
	data.attempts = j["attempts"];
	return data;
}
void append_reset(string ip) {
	while (true) {
		for (auto it = connection_data.begin(); it != connection_data.end(); ++it) if (it->first == ip)
		{
			if (it->second.attempts > requests) {
				this_thread::sleep_for(chrono::seconds(r_seconds));
				it->second.attempts -= requests;
				connection data = LoadConnectionData(ip);
				data.attempts = it->second.attempts;
				SaveConnectionData(data, it->second.ip);
			}
		}
		this_thread::sleep_for(1ms);
	}
}
bool request(const httplib::Request req)
{
	ifstream r("connection/" + req.remote_addr);
	if (not r.is_open()) {
		connection new_data;
		new_data.ip = req.remote_addr;
		new_data.attempts = 1;
		SaveConnectionData(new_data, req.remote_addr);
		connection_data.emplace(req.remote_addr, new_data);
	}
	else for (auto it = connection_data.begin(); it != connection_data.end(); ++it) if (it->first == req.remote_addr)
	{
		it->second.attempts++;
		if (it->second.attempts > requests) {
			backtasks.emplace_back(append_reset, req.remote_addr);
			return false;
		}
		connection data = LoadConnectionData(req.remote_addr);
		data.attempts = it->second.attempts;
		SaveConnectionData(data, it->second.ip);
	}
	return true;
}
int main()
{
	for (const auto& i : filesystem::directory_iterator("./connection/")) if (not filesystem::is_directory(i.path()))
	{
		connection data = LoadConnectionData(i.path().filename().string());
		connection_data.emplace(i.path().filename().string(), data);
	}
	server.Post(("/growtopia/server_data.php"), [&](const httplib::Request& req, httplib::Response& res) {
		future<bool> Request = async(request, req); Request.wait();
	if (not Request.get()) {
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
		cerr << req.remote_addr << " was rejected" << endl;
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
		return;
	}
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10);
	cerr << req.remote_addr << " has connected" << endl;
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
	res.set_content(server_data, "text/plain");
		});
	server.Get(("/growtopia/server_data.php"), [&](const httplib::Request& req, httplib::Response& res) { res.set_content(gov, "text/html"); });
	server.Get(("/cache"), [&](const httplib::Request& req, httplib::Response& res) { res.set_content(gov, "text/html"); });
	server.listen("0.0.0.0", 443);
	return 0;
}
