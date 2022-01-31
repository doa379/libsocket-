#include <iostream>
#include <libsockpp/sock.h>

static const char HOST0[] { "www.openssl.org" };
static const char HOST1[] { "www.openssl.org" };
static const char PORT[] { "443" };

int main(const int ARGC, const char *ARGV[]) {
  sockpp::XHandle h0 { sockpp::Cb { }, sockpp::Req::GET, { }, { }, "/" };
  sockpp::XHandle h1 { sockpp::Cb { }, sockpp::Req::GET, { }, { }, "/" };
  try {
    sockpp::MultiClient<sockpp::Https> mc { 1.1, HOST0, PORT, 2 };
    mc.performreq({ h0, h1 }, 1000);
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
  } catch (const char E[]) { std::cerr << E << "\n"; }
  return 0;
}
