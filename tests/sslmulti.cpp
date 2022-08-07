#include <iostream>
#include <libsockpp/sock.h>

static const char HOST0[] { "www.openssl.org" };
static const char HOST1[] { "www.openssl.org" };
static const char PORT[] { "443" };

int main(const int ARGC, const char *ARGV[]) {
  sockpp::Client_cb gen_writer {
    [](const std::string &buffer) {
      std::cout << "The response body:\n===================\n";
      std::cout << buffer << "\n";
    }
  };
  
  sockpp::Handle::Xfr h0 { { sockpp::Meth::GET, { }, { }, "/" }, gen_writer };
  sockpp::Handle::Xfr h1 { { sockpp::Meth::GET, { }, { }, "/" }, gen_writer };
  try {
    sockpp::MultiClient<sockpp::Https> mc { 1.1, HOST0, PORT, 2 };
    std::vector<std::reference_wrapper<sockpp::Handle::Xfr>> H { h0, h1 };
    mc.performreq(H, 1000);
    std::cout << "All transfer(s) completed\n";
    std::cout << "(Handle0):\n===================\n";
    std::cout << "The response header:\n===================\n";
    std::cout << h0.header() << std::endl;
    std::cout << "(Handle1):\n===================\n";
    std::cout << "The response header:\n===================\n";
    std::cout << h1.header() << std::endl;
  } catch (const std::exception &e) { std::cerr << e.what() << "\n"; }
  return 0;
}
