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
      sockpp::Recv<sockpp::Http> recv { sock };
      std::string cli_head, cli_body;
      recv.req_header(cli_head);
      recv.req_body(cli_body, cli_head);
      std::cout << "-Receive from client-\n";
      std::cout << cli_head << "\n";
      std::cout << cli_body << "\n";
      std::cout << "-End receive from client-\n";
      const std::string header { 
        std::string("HTTP/1.1 OK\r\n") + 
          std::string("Transfer-Encoding: chunked\r\n") + "\r\n" };
      if (!sock.write(header))
        return;
      sockpp::Time time;
      auto now { time.now() };
      while (time.diffpt<std::chrono::milliseconds>(time.now(), now) < 1500)
      {
        auto s { std::to_string(pow(2, sockpp::rand(8, 32))) };
        std::string document { sockpp::to_base16(s.size() + 2) + "\r\n" + s + "\r\n" };
        if (!sock.write(document))
          break;
        std::cout << "Sent to client " << s << std::endl;
        now = time.now();
        std::this_thread::sleep_for(std::chrono::milliseconds(sockpp::rand(500, 2000)));
      }

      std::cout << "Server timeout\n";
    } 
  };
  
  try {
    sockpp::Server<sockpp::Http> server(hostname, port_no);
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
