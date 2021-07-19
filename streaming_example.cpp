#include <iostream>
#include "socket.h"

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
    HttpClient client(1.1, hostname, port_no);
    Cb cb { [](const std::string &buffer) { std::cout << buffer; } };
    client.set_cb(cb);
    client.set_timeout(1750);
    if (client.connect())
    {
      if (!client.sendreq(GET, "/", { }, { }))
        throw client.report();

      client.recvreq();
      std::cout << "Stream disconnected\n";
      std::cout << "The response header:\n===================\n";
      std::cout << client.resp_header() << std::endl;
    }

    else
      throw client.report();
  }

  catch (const std::string &e) {
    std::cout << e << std::endl;
  }

  return 0;
}
