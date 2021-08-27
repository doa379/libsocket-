#include <iostream>
#include <libsockpp/sock.h>

static const std::string host0 { "webscantest.com" };
static const std::string host1 { "localhost" };
static const unsigned port { 80 };

int main(int argc, char *argv[])
{
  std::string hostname;
  unsigned port_no;
  if (argc != 3)
  {
    std::cerr << "Usage: ./client_example <hostname> <port>\n";
    hostname = host0;
    port_no = port;
  }

  else
  {
    hostname = std::string(argv[1]);
    port_no = std::atoi(argv[2]);
  }

  // Chunked transfer
  sockpp::Cb cb { [](const std::string &buffer) { std::cout << buffer; } };
  sockpp::XHandle h { cb };
  try {
    sockpp::Client<sockpp::Http> client(1.1, hostname, port_no);
    // Perform request on handle
    if (!client.performreq(h))
      throw "Unable to sendreq()";

    std::cout << "The response header:\n===================\n";
    std::cout << h.header << std::endl;
    std::cout << "The response body:\n===================\n";
    std::cout << h.body << std::endl;
  }

  catch (const char e[]) {
    std::cout << std::string(e) << std::endl;
  }

  return 0;
}
