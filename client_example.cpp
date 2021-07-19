#include <iostream>
#include "socket.h"

static const std::string host0 { "webscantest.com" };
static const unsigned port0 { 80 };
static const std::string host1 { "localhost" };
static const unsigned port1 { 80 };

int main(int argc, char *argv[])
{
  std::string hostname;
  unsigned port_no;
  if (argc != 3)
  {
    std::cerr << "Usage: ./client_example <hostname> <port>\n";
    hostname = host0;
    port_no = port0;
  }

  else
  {
    hostname = std::string(argv[1]);
    port_no = std::atoi(argv[2]);
  }

  try {
    HttpClient client(1.1, hostname, port_no);
    if (client.connect())
    {
      if (!client.sendreq(GET, "/", { }, { }))
        throw client.report();

      client.recvreq();
      std::cout << "The response header:\n===================\n";
      std::cout << client.resp_header() << std::endl;
      std::cout << "The response body:\n===================\n";
      std::cout << client.resp_body() << std::endl;
    }

    else
      throw client.report();
  }

  catch (const std::string &e) {
    std::cout << e << std::endl;
  }
  return 0;
}
