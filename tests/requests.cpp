// Example demonstrates a persistant server that likewise fields 
// requests from a client. The library polls for new connections
// then this example picks up polling requests. The server stays
// open and running for the lifetime of the server program.


#include <iostream>
#include <thread>
#include <cmath>
#include <csignal>
#include <libsockpp/sock.h>
#include <libsockpp/utils.h>
#include <libsockpp/time.h>

static const char PORT[] { "8080" };

int main(const int ARGC, const char *ARGV[]) {
  signal(SIGPIPE, SIG_IGN);
  auto cb {
    [&](sockpp::Http &sock) -> bool {
      sockpp::Recv<sockpp::Http> recv { 1000 };
      std::string cli_head, cli_body;
      // Recv determines if client is still at socket
      if (!recv.req_header(sock, cli_head))
        return false;
      recv.req_body(sock, cli_body, recv.parse_cl(cli_head));
      std::cout << "Received from client\n";
      auto s { std::to_string(pow(2, sockpp::rand(8, 32))) };
      const std::string document { s + "\r\n" };
      const std::string header { 
          "Content-Length: " + std::to_string(document.size()) + "\r\n\r\n"
      };

      if (!sock.write(header + document))
        return false;
      std::cout << "Sent to client " << s << std::endl;
      std::cout << "Server response end\n";
      std::cout << "Client at server exit\n";
      return true;
    }
  };
  
  try {
    sockpp::Server<sockpp::Http> server { PORT };
    std::cout << "Running HTTP server...\n";
    server.run(cb);
  } catch (const std::exception &e) { std::cerr << e.what() << std::endl; }
  return 0;
}
