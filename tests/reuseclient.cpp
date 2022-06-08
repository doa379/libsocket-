#include <iostream>
#include <thread>
#include <chrono>
#include <libsockpp/sock.h>

static const char HOST[] { "localhost" };
static const char PORT[] { "8080" };
using ConnType = sockpp::Http;

int main(const int ARGC, const char *ARGV[]) {
  // Chunked transfer
  sockpp::Client_cb cb { [](const std::string &buffer) { std::cout << "Recv from server " << buffer; } };
  sockpp::XHandle h { cb, sockpp::Req::GET, { }, { } };
  try {
    sockpp::Client<ConnType> client { 1.1, HOST, PORT };
    for (auto i { 0 }; i < 10; i++) {
      // Perform request on handle
      if (!client.performreq(h))
        throw "Unable to performreq()";
      // Reuse client connexion
      std::cout << "Received from server " << h.body;
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
  } catch (const std::exception &e) { std::cerr << e.what() << std::endl; }
  return 0;
}
