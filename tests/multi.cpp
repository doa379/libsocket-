#include <iostream>
#include <libsockpp/sock.h>

static const std::string host1 { "webscantest.com" };
static const std::string host0 { "localhost" };
static const unsigned port { 80 };

int main(int argc, char *argv[])
{
  sockpp::XHandle h0 { sockpp::Cb { }, GET, { }, { }, "/" };
  sockpp::XHandle h1 { sockpp::Cb { }, GET, { }, { }, "/" };
  sockpp::XHandle h2 { sockpp::Cb { }, GET, { }, { }, "/" };
  sockpp::XHandle h3 { sockpp::Cb { }, GET, { }, { }, "/" };
  try {
    sockpp::Client<sockpp::Http> client0 { 1.1, host0, port }, 
      client1 { 1.1, host0, port },
      client2 { 1.1, host0, port };
    sockpp::Multi<sockpp::Http> M { { client0, client1 } };
    std::vector<std::reference_wrapper<sockpp::XHandle>> H { { h0, h1, h2, h3 } };
    M.performreq(H);
    std::cout << "All transfer(s) completed\n";
    for (auto i { 0U }; i < H.size(); i++)
    {
      std::cout << "(Handle" << i << "):\n===================\n";
      std::cout << "The response header:\n===================\n";
      std::cout << H[i].get().header << std::endl;
      std::cout << "The response body:\n===================\n";
      std::cout << H[i].get().body << std::endl;
    }
  }

  catch (const char e[]) {
    std::cout << std::string(e) << std::endl;
  }

  return 0;
}
