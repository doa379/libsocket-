#include <iostream>
#include "socket.h"

int main(int argc, char *argv[])
{
  HttpClient client(1.1);
  if (client.connect("localhost", 8080))
  {
    if (!client.sendreq(GET, "/", { }, { }))
    {
      std::cout << client.get_report() << std::endl;
      return 1;
    }
    client.recvreq();
    std::cout << "The response header:\n===================\n";
    std::cout << client.get_header() << std::endl;
    std::cout << "The response body:\n===================\n";
    std::cout << client.get_response() << std::endl;
  }
  
  return 0;
}
