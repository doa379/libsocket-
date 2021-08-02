#include <iostream>
#include "sock.h"

static const std::string host0 { "www.openssl.org" };
static const unsigned port0 { 443 };
static const std::string host1 { "www.openssl.org" };
static const unsigned port1 { 443 };

int main(const int argc, const char *argv[])
{
  auto client0 { std::make_shared<Client<SSock>>(1.1, host0, port0, 2500) }, 
    client1 { std::make_shared<Client<SSock>>(1.1, host1, port1, 2500) };
  MultiSync<SSock> M;
  M.reg_client(*client0);
  M.reg_client(*client1);
  auto conn { M.connect() };
  std::cout << std::to_string(conn) << " connections established\n";
  client0->sendreq(GET, "/");
  client1->sendreq(GET, "/");
  // With a timeout 30 sec
  M.recvreq<std::chrono::seconds>(30);
  std::cout << "All transfer(s) completed\n";
  std::cout << "(Client0):\n===================\n";
  std::cout << "The response header (client0):\n===================\n";
  std::cout << client0->header() << std::endl;
  std::cout << "The response body (client0):\n===================\n";
  std::cout << client0->body() << std::endl;
  std::cout << "(Client1):\n===================\n";
  std::cout << "The response header (client1):\n===================\n";
  std::cout << client1->header() << std::endl;
  std::cout << "The response body (client1):\n===================\n";
  std::cout << client1->body() << std::endl;
  return 0;
}
