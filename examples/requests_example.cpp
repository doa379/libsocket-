#include <iostream>
#include <thread>
#include <cmath>
#include <csignal>
#include <libsockpp/sock.h>
#include <libsockpp/utils.h>
#include <libsockpp/time.h>

static const std::string host { "localhost" };
static const unsigned port { 8080 };

int main(const int argc, const char *argv[])
{
  std::string hostname;
  unsigned port_no;
  if (argc != 3)
  {
    std::cerr << "Usage: ./server_example <hostname> <port>\n";
    hostname = host;
    port_no = port;
  }

  else
  {
    hostname = std::string(argv[1]);
    port_no = std::atoi(argv[2]);
  }

  signal(SIGPIPE, SIG_IGN);
  auto cb {
    [&](sockpp::Http &sock) {
      while (1)
        if (sock.poll(250))
        {
          sockpp::Recv<sockpp::Http> recv { sock };
          std::string cli_head, cli_body;
          recv.req_header(cli_head);
          recv.req_body(cli_body, cli_head);
          std::cout << "-Receive from client-\n";
          std::cout << cli_head << "\n";
          std::cout << cli_body << "\n";
          std::cout << "-End receive from client-\n";
          auto s { std::to_string(pow(2, sockpp::rand(8, 32))) };
          const std::string document { s + "\r\n" };
          const std::string header { 
            std::string("HTTP/1.1 OK\r\n") +
              "Content-Length: " + std::to_string(document.size()) + "\r\n\r\n"
          };

          if (!sock.write(header + document))
            return;
          std::cout << "Sent to client " << s << std::endl;
          std::cout << "Server response end\n";
        }
    }
  };
  
  try {
    sockpp::Server<sockpp::Http> server { hostname, port_no };
    std::cout << "Running server...\n";
    while (1)
    {
      if (server.poll_listen(100))
      {
        std::cout << "Receive new client\n";
        server.recv_client(cb);
      }

      server.refresh_clients();
    }
  }

  catch (const char e[]) {
    std::cout << std::string(e) << std::endl;
  }

  return 0;
}
