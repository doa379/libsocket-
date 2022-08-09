#include <iostream>
#include <thread>
#include <cmath>
#include <csignal>
#include <libsockpp/sock.h>
#include <libsockpp/utils.h>

static const char PORT[] { "4433" };

int main(int ARGC, char *ARGV[]) {
  signal(SIGPIPE, SIG_IGN);
  sockpp::Client_cb gen_writer {
    [](const char p) { std::cout << p; }
  };
  
  auto client_msg { 
    [&](sockpp::Https &sock) {
      sockpp::Recv<sockpp::Https> recv { 1000 };
      std::string cli_head;
      if (recv.reqhdr(sock, cli_head)) {
        recv.reqbody(sock, gen_writer, recv.parsecl(cli_head));
        std::cout << "-Receive from client-\n";
        std::cout << cli_head << "\n";
        std::cout << "-End receive from client-\n";
      }
    }
  };

  auto cb { 
    [&](sockpp::Https &sock) -> bool {
      client_msg(sock);
      const std::string document { "Document" }, 
            header { 
                std::string("Content-Length: ") + 
                  std::to_string(document.size()) + 
                    std::string("\r\n") +
                      "\r\n" };
      return sock.write(header + document) ? true : false;
    }
  };

  auto chunked_cb { 
    [&](sockpp::Https &sock) -> bool {
      client_msg(sock);
      const std::string header { 
          std::string("Transfer-Encoding: chunked\r\n") + "\r\n" };
      if (!sock.write(header))
        return false;
      std::string document;
      while (1) {
        auto s { std::to_string(pow(2, sockpp::rand(8, 32))) };
        std::cout << s << std::endl;
        document = sockpp::to_base16(s.size() + 2) + "\r\n" + s + "\r\n";
        if (!sock.write(document))
          return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(sockpp::rand(500, 2000)));
      }
      // Blocks indefinitely at the server end
      return true;
    }
  };
  
  try {
    sockpp::Server<sockpp::Https> server { PORT };
    std::cout << "Running SSL server...\n";
    server.run(cb);
  } catch (const std::exception &e) { std::cerr << e.what() << std::endl; }
  
  return 0;
}
