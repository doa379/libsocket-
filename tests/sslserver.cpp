#include <iostream>
#include <thread>
#include <cmath>
#include <csignal>
#include <libsockpp/sock.h>
#include <libsockpp/utils.h>

static const char PORT[] { "4433" };

int main(int ARGC, char *ARGV[]) {
  signal(SIGPIPE, SIG_IGN);
  auto client_msg { 
    [&](sockpp::Https &sock) {
      sockpp::Recv<sockpp::Https> recv { sock };
      std::string cli_head, cli_body;
      if (recv.req_header(cli_head)) {
        recv.req_body(cli_body, recv.parse_cl(cli_head));
        std::cout << "-Receive from client-\n";
        std::cout << cli_head << "\n";
        std::cout << cli_body << "\n";
        std::cout << "-End receive from client-\n";
      }
    }
  };

  auto cb { 
    [&](sockpp::Https &sock) {
      client_msg(sock);
      const std::string document { "Document" }, 
            header { 
                std::string("Content-Length: ") + std::to_string(document.size()) + std::string("\r\n") +
                "\r\n" };
      sock.write(header + document);
    }
  };

  auto chunked_cb { 
    [&](sockpp::Https &sock) {
      client_msg(sock);
      const std::string header { 
          std::string("Transfer-Encoding: chunked\r\n") + "\r\n" };
      if (!sock.write(header))
        return;
      std::string document;
      while (1) {
        auto s { std::to_string(pow(2, sockpp::rand(8, 32))) };
        std::cout << s << std::endl;
        document = sockpp::to_base16(s.size() + 2) + "\r\n" + s + "\r\n";
        if (!sock.write(document))
          break;
        std::this_thread::sleep_for(std::chrono::milliseconds(sockpp::rand(500, 2000)));
      }
    }
  };
  
  try {
    sockpp::Server<sockpp::Https> server { PORT };
    std::cout << "Running SSL server...\n";
    while (1) {
      if (server.poll_listen(100))
        server.recv_client(cb);
      server.refresh_clients();
    }
  } catch (const char E[]) { std::cout << E << std::endl; }
  return 0;
}
