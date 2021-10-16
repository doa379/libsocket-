#include <iostream>
#include <libsockpp/sock.h>

static const char HOST0[] { "webscantest.com" };
static const char HOST1[] { "localhost" };
static const char PORT[] { "http" };

int main(int ARGC, char *ARGV[])
{
  std::string hostname;
  if (ARGC != 2)
  {
    std::cerr << "Usage: ./client_example <hostname>\n";
    hostname = std::string(HOST0);
  }

  else
    hostname = std::string(ARGV[1]);

  // Chunked transfer
  sockpp::Cb cb { [](const std::string &buffer) { std::cout << buffer; } };
  sockpp::XHandle h { cb, GET, { }, { }, "/" };
  try {
    sockpp::Client<sockpp::Http> client { 1.1, hostname, PORT };
    // Perform request on handle
    if (!client.performreq(h))
      throw "Unable to sendreq()";

    std::cout << "The response header:\n===================\n";
    std::cout << h.header << std::endl;
    std::cout << "The response body:\n===================\n";
    std::cout << h.body << std::endl;
  }

  catch (const char e[]) {
    std::cout << std::string(e) << std::endl;
  }

  return 0;
}
