#include <iostream>
#include <libsockpp/sock.h>

static const std::string host { "localhost" };
static const unsigned port { 8080 };

int main(int argc, char *argv[])
{
  std::string hostname;
  unsigned port_no;
  if (argc != 3)
  {
    std::cerr << "Usage: ./streaming_example <hostname> <port>\n";
    hostname = host;
    port_no = port;
  }

  else
  {
    hostname = std::string(argv[1]);
    port_no = std::atoi(argv[2]);
  }

  sockpp::Cb cb { [](const std::string &buffer) { std::cout << "Received " << buffer; } };
  sockpp::XHandle h { cb, POST, { "OK" }, "Some Data", "/" };
  while (1)
  {
    try {
      // Connect implicitly in scope
      sockpp::Client<sockpp::Http> client(1.1, hostname, port_no);
      if (!client.performreq(h))
        throw "Unable to sendreq()";
      std::cout << "Stream disconnected\n";
      std::cout << "The response header:\n===================\n";
      std::cout << h.header << std::endl;
      std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    }
  
    catch (const char e[]) {
      std::cout << std::string(e) << std::endl;
    }
  }

  return 0;
}
