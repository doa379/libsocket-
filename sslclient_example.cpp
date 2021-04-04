#include <iostream>
#include "socket.h"

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
  
  HttpsClient client(1.1);
  if (client.connect(hostname, port_no))
  {
    if (!client.sendreq(GET, "/", { }, { }))
    {
      std::cout << client.get_report() << std::endl;
      return 1;
    }
    client.recvreq();
    std::cout << client.get_report() << std::endl;
    std::cout << "The response header:\n===================\n";
    std::cout << client.get_header() << std::endl;
    std::cout << "The response body:\n===================\n";
    std::cout << client.get_response() << std::endl;
  }
  
  else
    std::cout << client.get_report() << std::endl;

  return 0;
}
