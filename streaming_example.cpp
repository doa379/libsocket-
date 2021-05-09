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
    std::cerr << "Usage: ./client_example <hostname> <port>\n";
    hostname = host0;
    port_no = port0;
  }

  else
  {
    hostname = std::string(argv[1]);
    port_no = std::atoi(argv[2]);
  }

  HttpClient client(1.1, hostname, port_no);
  Cb cb { [](const std::string &buffer) { std::cout << buffer; } };
  client.set_cb(cb);
  //client.set_timeout(2000);
  if (client.connect())
  {
    if (!client.sendreq(GET, "/", { }, { }))
    {
      std::cout << client.get_report() << std::endl;
      return 1;
    }
    client.recvreq_raw();
    std::cerr << "Stream disconnected\n";
  }

  else
    std::cout << client.get_report() << std::endl;
  return 0;
}
