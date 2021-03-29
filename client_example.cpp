#include <iostream>
#include "socket.h"

int main(int argc, char *argv[])
{
  ClientSocket client(1.1);
  if (client.connect("localhost", 80))
  {
    if (!client.sendreq(GET, "/", { }, { }))
    {
      std::cout << client.get_report() << std::endl;
      return 1;
    }
    char buffer[512];
    client.recvreq(buffer, sizeof buffer);
    std::cout << std::string(buffer) << std::endl;
  }
  
  return 0;
}
