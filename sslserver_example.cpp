#include <iostream>
#include "socket.h"

static const std::string host0 { "localhost" };
static const unsigned port0 { 4433 };
static const std::string host1 { "..." };
static const unsigned port1 { 8080 };

int main(int argc, char *argv[])
{
  std::string hostname;
  unsigned port_no;
  if (argc != 3)
  {
    std::cerr << "Usage: ./sslserver_example <hostname> <port>\n";
    hostname = host0;
    port_no = port0;
  }

  else
  {
    hostname = std::string(argv[1]);
    port_no = std::atoi(argv[2]);
  }

  HttpsServer server;
  if (!server.connect(hostname, port_no))
  {
    std::cout << server.get_report() << std::endl;
    return 1;
  }

  server.run("Document being served\n");
  return 0;
}
