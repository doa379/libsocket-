#include <iostream>
#include <libsockpp/sock.h>

static const char HOST[] { "www.openssl.org" };
static const char PORT[] { "https" };

int main(int ARGC, char *ARGV[]) {
  std::string host { HOST }, port { PORT }, endp { "/" };
  if (ARGC != 4)
    std::cerr << "Usage: ./sslclient <host> <port> <endp>\n";
  else {
    host = std::string(ARGV[1]);
    port = std::string(ARGV[2]);
    endp = std::string(ARGV[3]);
  }

  sockpp::Client_cb writer_cb {
    [&](const char p) { std::cout << p; }
  };
  
  sockpp::Handle::Xfr h { 
    { sockpp::Meth::GET, { "Connection: close" }, { }, endp }, 
    writer_cb
  };
  
  try {
    sockpp::Client<sockpp::Https> client { 1.1, host.c_str(), port.c_str() };
    // Perform request on handle
    if (!client.performreq(h))
      throw "Failed to performreq()";
    std::cout << "The response header:\n===================\n";
    std::cout << h.header() << std::endl;
  } catch (const std::exception &e) { std::cerr << e.what() << std::endl; }
  return 0;
}
