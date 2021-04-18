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
  HttpClient client0(1.1, host0, port0), client1(1.1, host1, port1);
  MultiHttpClient mc(10);
  mc.set_client(client0);
  mc.set_client(client1);
  if (!mc.connect())
    std::cerr << "There was at least one failure in connecting, proceeding...\n";
  client0.sendhttpreq(GET, "/", { }, { });
  client1.sendhttpreq(GET, "/", { }, { });
  mc.recvreq();
  std::cout << "All transfer(s) completed\n";
  std::cout << "(Client0):\n===================\n";
  std::cout << "The response header (client0):\n===================\n";
  std::cout << client0.get_header() << std::endl;
  std::cout << "The response body (client0):\n===================\n";
  std::cout << client0.get_response() << std::endl;
  std::cout << "(Client1):\n===================\n";
  std::cout << "The response header (client1):\n===================\n";
  std::cout << client1.get_header() << std::endl;
  std::cout << "The response body (client1):\n===================\n";
  std::cout << client1.get_response() << std::endl;
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
