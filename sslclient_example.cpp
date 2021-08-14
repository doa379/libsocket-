#include <iostream>
#include "sock.h"

static const std::string host0 { "www.openssl.org" };
static const unsigned port0 { 443 };
static const std::string host1 { "..." };
static const unsigned port1 { 443 };

int main(int argc, char *argv[])
{
  std::string hostname;
  unsigned port_no;
  if (argc != 3)
  {
    std::cerr << "Usage: ./sslclient_example <hostname> <port>\n";
    hostname = host0;
    port_no = port0;
  }

  else
  {
    hostname = std::string(argv[1]);
    port_no = std::atoi(argv[2]);
  }

  try {
    sockpp::Client<sockpp::HttpsCli> client(1.1, hostname, port_no);
    if (client.connect())
    {
      // No init on handle implies defaults: ident_cb GET { } { } "/"
      sockpp::XHandle h;
      // Perform request on handle, timeout 250ms
      if (!client.performreq<std::chrono::milliseconds>(250, h))
        throw "Unable to sendreq()";
      std::cout << "The response header:\n===================\n";
      std::cout << h.header << std::endl;
      std::cout << "The response body:\n===================\n";
      std::cout << h.body << std::endl;
    }

    else
      throw "Client connection failed";
  }

  catch (const char e[]) {
    std::cout << std::string(e) << std::endl;
  }

  return 0;
}
