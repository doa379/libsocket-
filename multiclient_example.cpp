#include <iostream>
#include "socket.h"

static const std::string host0 { "webscantest.com" };
static const unsigned port0 { 80 };
static const std::string host1 { "localhost" };
static const unsigned port1 { 80 };

int main(int argc, char *argv[])
{
/*
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
*/
  HttpClient client0(1.1), client1(1.1);
  MultiHttpClient multi_client(60);
  multi_client.set_client(client0);
  multi_client.set_client(client1);
  client0.connect(host0, port0);
  client1.connect(host1, port1);
  /*
  if (client.connect(hostname, port_no))
  {
    if (!client.sendreq(GET, "/", { }, { }))
    {
      std::cout << client.get_report() << std::endl;
      return 1;
    }
    client.recvreq();
    std::cout << "The response header:\n===================\n";
    std::cout << client.get_header() << std::endl;
    std::cout << "The response body:\n===================\n";
    std::cout << client.get_response() << std::endl;
  }

  else
    std::cout << client.get_report() << std::endl;
    */
  return 0;
}
