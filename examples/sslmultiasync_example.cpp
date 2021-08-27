#include <iostream>
#include <libsockpp/sock.h>

static const std::string host0 { "www.openssl.org" };
static const std::string host1 { "www.openssl.org" };
static const unsigned port { 443 };

int main(const int argc, const char *argv[])
{
  sockpp::XHandle h0 { sockpp::Cb { }, GET, { }, { }, "/"  };
  sockpp::XHandle h1 { sockpp::Cb { }, GET, { }, { }, "/"  };
  try {
    sockpp::Client<sockpp::Https> client0 { 1.1, host0, port }, 
      client1 { 1.1, host1, port };
    sockpp::Multi<sockpp::Https> M { { client0, client1 } };
    // Perform using 2 async xfrs
    M.performreq(2, { h0, h1 });
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
    std::cerr << std::string(e) << "\n";
  }

  return 0;
}
