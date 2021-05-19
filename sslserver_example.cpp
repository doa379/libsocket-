#include <iostream>
#include <thread>
#include <cmath>
#include <csignal>
#include "socket.h"
#include "utils.h"

static const std::string host0 { "localhost" };
static const unsigned port0 { 4433 };

int main(int argc, char *argv[])
{
  std::string hostname;
  unsigned port_no;
  if (argc != 3)
  {
    std::cerr << "Usage: ./sslserver_example <hostname> <port>\n";
    hostname = host0;
    port_no = port0;
  }

  else
  {
    hostname = std::string(argv[1]);
    port_no = std::atoi(argv[2]);
  }

  signal(SIGPIPE, SIG_IGN);
  HttpsServer server(hostname, port_no);
  if (!server.connect())
  {
    std::cout << server.get_report() << std::endl;
    return 1;
  }

  auto cb { 
    [&](const std::any arg) {
      std::shared_ptr<LocalSecureClient> client { std::any_cast<std::shared_ptr<LocalSecureClient>>(arg) };
      const std::string header { 
        std::string("HTTP/1.1 SSL Stream OK\r\n") +
        std::string("Transfer-Encoding: chunked\r\n") +
        hostname + ":" + std::to_string(port_no) + "\r\n\r\n" };
      if (client->sslserver->write(header) < 0)
        return;
      std::string document;
      while (1)
      {
        auto s { std::to_string(pow(2, rand(8, 32))) };
        std::cout << s << std::endl;
        document = to_base16(s.size() + 2) + "\r\n" + s + "\r\n";
        if (client->sslserver->write(document) < 0)
          break;
        std::this_thread::sleep_for(std::chrono::milliseconds(rand(500, 2000)));
      }

      server.close_client(*client);
    }
  };

  std::cout << "Running SSL server...\n";
  while (1)
  {
    auto client { std::make_shared<LocalSecureClient>(server.recv_client()) };
    if (client->clientsd > -1)
      server.new_client(cb, client);
   
    server.refresh_clients();
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  return 0;
}
