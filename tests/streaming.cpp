#include <iostream>
#include <libsockpp/sock.h>

static const char HOST[] { "127.0.0.1" };
static const char PORT[] { "8080" };

int main(int ARGC, char *ARGV[]) {
  sockpp::Client_cb writer_cb {
    [](const char p) { 
      std::cout << p; 
    }
  };
  
  sockpp::Handle::Xfr h { 
    { sockpp::Meth::POST, { "Some Header", "Some Header" }, "Some Data", "/" },
    writer_cb
  };

  try {
    sockpp::Client<sockpp::Http> client { HOST, PORT };
    while (1) {
      if (!client.performreq(h))
        throw "Unable to sendreq()";
      std::cout << "Stream disconnected\n";
      std::cout << "The response header:\n===================\n";
      std::cout << h.header() << std::endl;
    }
  } catch (const std::exception &e) { std::cerr << e.what() << std::endl; }
  return 0;
}
