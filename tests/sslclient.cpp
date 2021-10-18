#include <iostream>
#include <libsockpp/sock.h>

static const char HOST[] { "www.openssl.org" };
static const char PORT[] { "https" };

int main(int ARGC, char *ARGV[])
{
  std::string hostname { HOST }, endp { "/" };
  if (ARGC != 3)
    std::cerr << "Usage: ./sslclient_example <hostname> <endp>\n";

  else
  {
    hostname = std::string(ARGV[1]);
    endp = std::string(ARGV[2]);
  }

  sockpp::Cb cb { [&](const std::string &buffer) { std::cout << buffer; } };
  sockpp::XHandle h { cb, GET, { { "Connection: close" } }, { }, endp };
  try {
    sockpp::Client<sockpp::Https> client { 1.1, hostname, PORT };
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
