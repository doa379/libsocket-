#include <iostream>
#include <thread>
#include <cmath>
#include <csignal>
#include "socket.h"
#include "utils.h"

static const std::string host0 { "localhost" };
static const unsigned port0 { 8080 };

int main(const int argc, const char *argv[])
{
  std::string hostname;
  unsigned port_no;
  if (argc != 3)
  {
    std::cerr << "Usage: ./server_example <hostname> <port>\n";
    hostname = host0;
    port_no = port0;
  }

  else
  {
    hostname = std::string(argv[1]);
    port_no = std::atoi(argv[2]);
  }

  signal(SIGPIPE, SIG_IGN);
  try {
    Server<Sock> server(hostname, port_no);
    if (!server.connect())
      throw "Server unable to connect";

    auto cb { 
      //[&](const std::any arg) {
        //auto sock { std::any_cast<std::shared_ptr<Sock>>(arg) };
      [&](Sock &sock) {
        const std::string header { 
          std::string("HTTP/1.1 Stream OK\r\n") + 
            std::string("Transfer-Encoding: chunked\r\n") +
            hostname + ":" + std::to_string(port_no) + "\r\n\r\n" };
        if (!sock.write(header))
          return;
        std::string document;
        while (1)
        {
          auto s { std::to_string(pow(2, rand(8, 32))) };
          std::cout << s << std::endl;
          document = to_base16(s.size() + 2) + "\r\n" + s + "\r\n";
          if (!sock.write(document))
            break;
          std::this_thread::sleep_for(std::chrono::milliseconds(rand(500, 2000)));
        }
      } 
    };

    std::cout << "Running server...\n";
    while (1)
    {
      if (server.poll_listen(100))
      {
        //auto sock { std::make_shared<Sock>(server.recv_client()) };
        auto sock { server.recv_client() };
        server.new_client(sock, cb);
      }

      server.refresh_clients();
    }
  }

  catch (const std::string &e) {
    std::cout << e << std::endl;
  }

  return 0;
}
