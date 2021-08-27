#include <iostream>
#include <libsockpp/sock.h>

static const std::string host0 { "localhost" };
static const std::string host1 { "webscantest.com" };
static const std::string host { host0 };
static const unsigned port { 80 };
using ConnType = sockpp::Http;

int main(const int argc, const char *argv[])
{
  // Chunked transfer
  sockpp::Cb cb { [](const std::string &buffer) { std::cout << buffer; } };
  sockpp::XHandle h { cb };
  for (auto i { 0 }; i < 2; i++)
  {
    try {
      sockpp::Client<ConnType> client(1.1, host, port);
      // Perform request on handle
      if (!client.performreq(h))
        throw "Unable to performreq()";

      std::cout << "The response header:\n===================\n";
      std::cout << h.header << std::endl;
      std::cout << "The response body:\n===================\n";
      std::cout << h.body << std::endl;
    }

    catch (const char e[]) {
      std::cout << std::string(e) << std::endl;
    }
  }

  return 0;
}
