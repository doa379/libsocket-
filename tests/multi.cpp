#include <iostream>
#include <libsockpp/sock.h>

static const char HOST0[] { "localhost" };
static const char HOST1[] { "webscantest.com" };
static const char PORT[] { "80" };

int main(int ARGC, char *ARGV[]) {
  sockpp::XHandle h0 { sockpp::Client_cb { }, sockpp::Req::GET, { }, { }, "/" };
  sockpp::XHandle h1 { sockpp::Client_cb { }, sockpp::Req::GET, { }, { }, "/" };
  sockpp::XHandle h2 { sockpp::Client_cb { }, sockpp::Req::GET, { }, { }, "/" };
  sockpp::XHandle h3 { sockpp::Client_cb { }, sockpp::Req::GET, { }, { }, "/" };
  try {
    sockpp::MultiClient<sockpp::Http> mc { 1.1, HOST1, PORT, 4 };
    std::vector<std::reference_wrapper<sockpp::XHandle>> H { { h0, h1, h2, h3 } };
    mc.performreq(H, 2000);
    std::cout << "All transfer(s) completed\n";
    for (auto i { 0U }; i < H.size(); i++) {
      std::cout << "(Handle" << i << "):\n===================\n";
      std::cout << "The response header:\n===================\n";
      std::cout << H[i].get().header << std::endl;
      std::cout << "The response body:\n===================\n";
      std::cout << H[i].get().body << std::endl;
    }
  } catch (const std::exception &e) { std::cerr << e.what() << std::endl; }
  return 0;
}
