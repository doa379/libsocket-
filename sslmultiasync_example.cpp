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
  ClientHandle<SSock> handle0 { 
    *client0, ident_cb, GET, "/", { }, { }
  };
  
  ClientHandle<SSock> handle1 {
    *client1, ident_cb, GET, "/", { }, { }
  };
  
  MultiAsync<SSock> M({ handle0, handle1 });
  auto conn { M.connect() };
  std::cout << std::to_string(conn) << " connections established\n";
  // 2 async connexions, Timeout 100ms (cap waits)
  M.performreq<std::chrono::milliseconds>(2, 100);
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
