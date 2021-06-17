#include <iostream>
#include "socket.h"

static const std::string host0 { "localhost" };
static const unsigned port0 { 4433 };

// Remember to generate a set of pems
// $ openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout /tmp/key.pem -out /tmp/cert.pem

int main(int argc, char *argv[])
{
  std::string hostname;
  unsigned port_no;
  if (argc != 3)
  {
    std::cerr << "Usage: ./sslstreaming_example <hostname> <port>\n";
    hostname = host0;
    port_no = port0;
  }

  else
  {
    hostname = std::string(argv[1]);
    port_no = std::atoi(argv[2]);
  }

  try {
    HttpsClient client(1.1, hostname, port_no);
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
      std::cout << client.header() << std::endl;
    }

    else
      throw client.report();
  }

  catch (const std::string &e) {
    std::cout << e << std::endl;
  }

  return 0;
}
