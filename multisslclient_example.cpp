#include <iostream>
#include "socket.h"

static const std::string host0 { "www.openssl.org" };
static const unsigned port0 { 443 };
static const std::string host1 { "localhost" };
static const unsigned port1 { 4433 };

int main(const int argc, const char *argv[])
{
  HttpsClient client0(1.1, host0, port0), client1(1.1, host1, port1);
  MultiClient mc;
  mc.set_client(client0);
  mc.set_client(client1);
  if (!mc.connect())
    std::cerr << "There was at least one failure in connecting, proceeding...\n";
  client0.sendreq(GET, "/", { }, { });
  client1.sendreq(GET, "/", { }, { });
  mc.recvreq(100);
  std::cout << "All transfer(s) completed\n";
  std::cout << "(Client0):\n===================\n";
  std::cout << "The response header (client0):\n===================\n";
  std::cout << client0.header() << std::endl;
  std::cout << "The response body (client0):\n===================\n";
  std::cout << client0.response() << std::endl;
  std::cout << "(Client1):\n===================\n";
  std::cout << "The response header (client1):\n===================\n";
  std::cout << client1.header() << std::endl;
  std::cout << "The response body (client1):\n===================\n";
  std::cout << client1.response() << std::endl;
  return 0;
}
