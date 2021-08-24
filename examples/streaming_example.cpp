#include <iostream>
#include <libsockpp/sock.h>

static const std::string host0 { "localhost" };
static const unsigned port0 { 8080 };

int main(int argc, char *argv[])
{
  std::string hostname;
  unsigned port_no;
  if (argc != 3)
  {
    std::cerr << "Usage: ./streaming_example <hostname> <port>\n";
    hostname = host0;
    port_no = port0;
  }

  else
  {
    hostname = std::string(argv[1]);
    port_no = std::atoi(argv[2]);
  }

  try {
    sockpp::Cb cb { [](const std::string &buffer) { std::cout << buffer; } };
    sockpp::XHandle h { cb, POST, { "OK" }, "Some Data", "/" };
    sockpp::Client<sockpp::Http> client(1.1, hostname, port_no);
    // Make a persistant connection here
    //if (!client.connect())
      //throw "Unable to connect()";
    while (1)
    {
      if (!client.connect())
        throw "Unable to connect()";
      // Data sent as POST request
      // Header validates request is OK
      // Chunked xfr will operate on cb() in handle
      if (!client.performreq(h))
        throw "Unable to sendreq()";
      std::cout << "Stream disconnected\n";
      std::cout << "The response header:\n===================\n";
      std::cout << h.header << std::endl;
    }
  }

  catch (const char e[]) {
    std::cout << std::string(e) << std::endl;
  }

  return 0;
}
