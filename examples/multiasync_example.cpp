#include <iostream>
#include <libsockpp/sock.h>

static const std::string host0 { "webscantest.com" };
static const unsigned port0 { 80 };
static const std::string host1 { "localhost" };
static const unsigned port1 { 80 };

int main(int argc, char *argv[])
{
  try {
    sockpp::Client<sockpp::Http> conn0 { 1.1, host0, port0 };
    sockpp::XHandle h0 { sockpp::Cb { }, GET, { }, { }, "/" };
    sockpp::Client<sockpp::Http> conn1 { 1.1, host1, port1 };
    sockpp::XHandle h1 { sockpp::Cb { }, GET, { }, { }, "/" };
    sockpp::Multi<sockpp::Http> M { { conn0, conn1 } };
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
  }

  catch (const char e[]) {
    std::cout << std::string(e) << std::endl;
  }

  return 0;
}
