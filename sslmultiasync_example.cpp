#include <iostream>
#include "sock.h"

static const std::string host0 { "www.openssl.org" };
static const unsigned port0 { 443 };
static const std::string host1 { "www.openssl.org" };
static const unsigned port1 { 443 };

int main(const int argc, const char *argv[])
{
  sockpp::Client<sockpp::HttpsCli> client0(1.1, host0, port0), 
    client1(1.1, host1, port1);
  sockpp::XHandle h0 { sockpp::Cb { }, GET, { }, { }, "/"  };
  sockpp::XHandle h1 { sockpp::Cb { }, GET, { }, { }, "/"  };
  sockpp::Multi<sockpp::HttpsCli> M({ client0, client1 });
  auto conn { M.connect() };
  std::cout << std::to_string(conn) << " connections established\n";
  // Timeout 100ms (cap waits), 2 async xfrs
  M.performreq<std::chrono::milliseconds>(100, 2, { h0, h1 });
  std::cout << "All async transfer(s) completed\n";
  std::cout << "(Client0):\n===================\n";
  std::cout << "The response header:\n===================\n";
  std::cout << h0.header << std::endl;
  std::cout << "The response body:\n===================\n";
  std::cout << h0.body << std::endl;
  std::cout << "(Client1):\n===================\n";
  std::cout << "The response header:\n===================\n";
  std::cout << h1.header << std::endl;
  std::cout << "The response body:\n===================\n";
  std::cout << h1.body << std::endl;
  return 0;
}
