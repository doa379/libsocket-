#include <iostream>
#include "socket.h"
#include <unistd.h>

int main(int argc, char *argv[])
{
  HttpsClient client(1.1);
  if (client.connect("www.google.com", 443))
  {
    if (!client.sendreq(GET, "/", { }, { }))
    {
      std::cout << client.get_report() << std::endl;
      return 1;
    }
    sleep(1);
    client.recvreq();
    std::cout << client.get_report() << std::endl;
    std::cout << "The response header:\n===================\n";
    std::cout << client.get_header() << std::endl;
    std::cout << "The response body:\n===================\n";
    std::cout << client.get_response() << std::endl;
  }
  
  else
    std::cout << client.get_report() << std::endl;

  //sleep(2);
  return 0;
}
