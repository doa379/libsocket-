#include <iostream>
#include "socket.h"

static const std::string host0 { "localhost" };
static const unsigned port0 { 8080 };
static const std::string host1 { "..." };
static const unsigned port1 { 8080 };

int main(int argc, char *argv[])
{
  std::string hostname;
  unsigned port_no;
  if (argc != 3)
  {
    std::cerr << "Usage: ./server_example <hostname> <port>\n";
    hostname = host0;
    port_no = port0;
  }

  else
  {
    hostname = std::string(argv[1]);
    port_no = std::atoi(argv[2]);
  }

  HttpServer server;
  if (!server.connect(hostname, port_no))
  {
    std::cout << server.get_report() << std::endl;
    return 1;
  }

  const std::string document { "Document being served at " +
    hostname + " port " + std::to_string(port_no) + '\n' },
        header { "Content-Length: " + std::to_string(document.size()) +
          "\r\n\r\n" };
  server.run(header + document);
  return 0;
}
