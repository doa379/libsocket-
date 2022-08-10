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
  sockpp::Client_cb writer_cb { [](const char p) { std::cout << p; } };
  sockpp::Handle::Xfr h { { sockpp::Meth::GET, { }, { }, "/" }, writer_cb };
  try {
    sockpp::Client<sockpp::Http> client { host.c_str(), PORT };
    // Perform request on handle
    if (!client.performreq(h))
      throw "Failed to performreq()";

    std::cout << "The response header:\n===================\n";
    std::cout << h.header() << std::endl;
  } catch (const std::exception &e) { std::cerr << e.what() << std::endl; }
  return 0;
}
