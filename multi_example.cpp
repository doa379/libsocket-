#include <iostream>
#include "sock.h"

static const std::string host0 { "webscantest.com" };
static const unsigned port0 { 80 };
static const std::string host1 { "localhost" };
static const unsigned port1 { 80 };

int main(int argc, char *argv[])
{
  try {
    sockpp::Client<sockpp::Http> client0(1.1, host0, port0), client1(1.1, host0, port0);
    sockpp::Multi<sockpp::Http> M({ client0, client1 });
    auto conn { M.connect() };
    std::cout << std::to_string(conn) << " connections established\n";
    sockpp::XHandle h0 { sockpp:: Cb { }, GET, { }, { }, "/" };
    sockpp::XHandle h1 { sockpp::Cb { }, GET, { }, { }, "/" };
    // With a timeout 30 sec
    M.performreq<std::chrono::milliseconds>(1000, { h0, h1 });
    std::cout << "All transfer(s) completed\n";
    std::cout << "(Handle0):\n===================\n";
    std::cout << "The response header:\n===================\n";
    std::cout << h0.header << std::endl;
    std::cout << "The response body:\n===================\n";
    std::cout << h0.body << std::endl;
    std::cout << "(Handle1):\n===================\n";
    std::cout << "The response header:\n===================\n";
    std::cout << h1.header << std::endl;
    std::cout << "The response body:\n===================\n";
    std::cout << h1.body << std::endl;
  }

  catch (const char e[]) {
    std::cout << std::string(e) << std::endl;
  }

  return 0;
}
