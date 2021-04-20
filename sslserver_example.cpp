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

  HttpsServer server(hostname, port_no);
  if (!server.connect())
  {
    std::cout << server.get_report() << std::endl;
    return 1;
  }

  std::cout << "Running SSL server on " << hostname << ":" << std::to_string(port_no) << std::endl;
  const std::string header { "HTTP/1.1 200 OK" },
    document { "Document" };
  server.run(header + "\r\n\r\n" + document);
  return 0;
}
