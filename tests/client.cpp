#include <iostream>
#include <libsockpp/sock.h>

static const char HOST0[] { "webscantest.com" };
static const char HOST1[] { "localhost" };
static const char PORT[] { "http" };

int main(int ARGC, char *ARGV[]) {
  std::string host { HOST0 };
  if (ARGC != 2)
    std::cerr << "Usage: ./client <host>\n";

  else
    host = std::string(ARGV[1]);

  // Chunked transfer
  sockpp::Cb cb { [](const std::string &buffer) { std::cout << buffer; } };
  sockpp::XHandle h { cb, GET, { }, { }, "/" };
  try {
    sockpp::Client<sockpp::Http> client { 1.1, host.c_str(), PORT };
    // Perform request on handle
    if (!client.performreq(h))
      throw "Failed to performreq()";

    std::cout << "The response header:\n===================\n";
    std::cout << h.header << std::endl;
    std::cout << "The response body:\n===================\n";
    std::cout << h.body << std::endl;
  } catch (const char E[]) { std::cout << E << std::endl; }
  return 0;
}
