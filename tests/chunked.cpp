#include <iostream>
#include <thread>
#include <cmath>
#include <csignal>
#include <libsockpp/sock.h>
#include <libsockpp/utils.h>
#include <libsockpp/time.h>

static const char PORT[] { "8080" };
static const char SSLPORT[] { "4433" };

int main(const int ARGC, const char *ARGV[]) {
  signal(SIGPIPE, SIG_IGN);
  auto cb { 
    [&](sockpp::Https &sock) -> bool { 
      sockpp::Recv<sockpp::Https> recv { 1000 };
      std::string cli_head, cli_body;
      if (recv.req_header(sock, cli_head))
        recv.req_body(sock, cli_body, recv.parse_cl(cli_head));
      else 
        return false;
      std::cout << "-Receive from client-\n";
      std::cout << cli_head << "\n";
      std::cout << cli_body << "\n";
      std::cout << "-End receive from client-\n";
      const std::string header {
        std::string("Transfer-Encoding: chunked\r\n") + "\r\n" };
      if (!sock.write(header))
        return false;
      sockpp::Time time;
      auto now { time.now() };
      while (time.diffpt<std::chrono::milliseconds>(time.now(), now) < 2000) {
        auto s { std::to_string(pow(2, sockpp::rand(8, 32))) };
        std::string document { sockpp::to_base16(s.size() + 2) + "\r\n" + s + "\r\n" };
        if (!sock.write(document))
          return false;
        std::cout << "Sent to client " << s << std::endl;
        now = time.now();
        std::this_thread::sleep_for(std::chrono::milliseconds(sockpp::rand(500, 2000)));
      }
      // Blocks at the server end subject to timeout
      return true;
    } 
  };

  try {
    sockpp::Server<sockpp::Https> server { SSLPORT };
    std::cout << "Running HTTP/S server...\n";
    server.run(cb);
  } catch (const std::exception &e) { std::cerr << e.what() << std::endl; }

  return 0;
}
