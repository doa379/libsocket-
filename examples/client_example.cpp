#include <iostream>
#include <libsockpp/sock.h>

static const std::string host0 { "webscantest.com" };
static const unsigned port0 { 80 };
static const std::string host1 { "localhost" };
static const unsigned port1 { 80 };

int main(int argc, char *argv[])
{
  std::string hostname;
  unsigned port_no;
  if (argc != 3)
  {
    std::cerr << "Usage: ./client_example <hostname> <port>\n";
    hostname = host0;
    port_no = port0;
  }

  else
  {
    hostname = std::string(argv[1]);
    port_no = std::atoi(argv[2]);
  }

  try {
    // Chunked transfer
    sockpp::Cb cb { [](const std::string &buffer) { std::cout << buffer; } };
    sockpp::Client<sockpp::Http> client(1.1, hostname, port_no);
    if (client.connect())
    {
      sockpp::XHandle h { cb };
      // Perform request on handle, timeout 500ms
      if (!client.performreq<std::chrono::milliseconds>(500, h))
        throw "Unable to sendreq()";

      std::cout << "The response header:\n===================\n";
      std::cout << h.header << std::endl;
      std::cout << "The response body:\n===================\n";
      std::cout << h.body << std::endl;
    }

    else
      throw "Client connection failed";
  }

  catch (const char e[]) {
    std::cout << std::string(e) << std::endl;
  }
  return 0;
}
