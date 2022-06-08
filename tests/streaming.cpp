#include <iostream>
#include <libsockpp/sock.h>

static const char HOST[] { "127.0.0.1" };
static const char PORT[] { "8080" };

int main(int ARGC, char *ARGV[]) {
  sockpp::Client_cb cb { [](const std::string &buffer) { std::cout << "Received " << buffer; } };
  sockpp::XHandle h { cb, sockpp::Req::POST, { "Some Header", "Some Header" }, "Some Data", "/" };
  try {
    sockpp::Client<sockpp::Http> client { 1.1, HOST, PORT };
    while (1) {
      if (!client.performreq(h))
        throw "Unable to sendreq()";
      std::cout << "Stream disconnected\n";
      std::cout << "The response header:\n===================\n";
      std::cout << h.header << std::endl;
      std::cout << "The response body:\n===================\n";
      std::cout << h.body << std::endl;
    }
  } catch (const std::exception &e) { std::cerr << e.what() << std::endl; }
  return 0;
}
