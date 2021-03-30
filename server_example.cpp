#include <iostream>
#include "socket.h"

int main(int argc, char *argv[])
{
  HttpServer server;
  if (!server.connect("localhost", 8080))
  {
    std::cout << server.get_report() << std::endl;
    return 1;
  }
  
  server.run();
  return 0;
}
