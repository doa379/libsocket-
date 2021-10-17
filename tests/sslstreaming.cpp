#include <iostream>
#include <libsockpp/sock.h>

static const char HOST[] { "localhost" };
static const char PORT[] { "4433" };

// Remember to generate a set of pems
// $ openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout /tmp/key.pem -out /tmp/cert.pem

int main(int ARGC, char *ARGV[])
{
  sockpp::Cb cb { [](const std::string &buffer) { std::cout << buffer; } };
  // Data sent as POST request
  // Header validates request is OK
  // Chunked transfer calls cb()
  sockpp::XHandle h { cb, POST, { "OK" }, "Some Data", "/" };

  try {
    sockpp::Client<sockpp::Https> client { 1.1, HOST, PORT };
    if (!client.performreq(h))
      throw "Unable to sendreq()";

    std::cout << "Stream disconnected\n";
    std::cout << "The response header:\n===================\n";
    std::cout << h.header << std::endl;
  }

  catch (const char e[]) {
    std::cout << std::string(e) << std::endl;
  }

  return 0;
}
