#include <iostream>
#include <thread>
#include <cmath>
#include <csignal>
#include <libsockpp/sock.h>
#include <libsockpp/utils.h>

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
  try {
    sockpp::Server<sockpp::HttpsSvr> server(hostname, port_no);
    if (!server.connect())
      throw "Server unable to connect";

    auto client_msg { 
      [&](sockpp::HttpsSvr &sock) {
        sockpp::Recv<sockpp::HttpsSvr> recv { sock };
        std::string cli_head, cli_body;
        recv.req_header(cli_head);
        recv.req_body(cli_body, cli_head);
        std::cout << "-Receive from client-\n";
        std::cout << cli_head << "\n";
        std::cout << cli_body << "\n";
        std::cout << "-End receive from client-\n";
      }
    };

    auto cb { 
      [&](sockpp::HttpsSvr &sock) {
        client_msg(sock);
        const std::string document { "Document" }, 
          header { 
            std::string("HTTP/1.1 OK\r\n") +
              std::string("Content-Length: ") + std::to_string(document.size()) + std::string("\r\n") +
                "\r\n" };
        sock.write(header + document);
      }
    };

    auto chunked_cb { 
      [&](sockpp::HttpsSvr &sock) {
        client_msg(sock);
        const std::string header { 
          std::string("HTTP/1.1 OK\r\n") +
            std::string("Transfer-Encoding: chunked\r\n") + "\r\n" };
        if (!sock.write(header))
          return;
        std::string document;
        while (1)
        {
          auto s { std::to_string(pow(2, sockpp::rand(8, 32))) };
          std::cout << s << std::endl;
          document = sockpp::to_base16(s.size() + 2) + "\r\n" + s + "\r\n";
          if (!sock.write(document))
            break;
          std::this_thread::sleep_for(std::chrono::milliseconds(sockpp::rand(500, 2000)));
        }
      }
    };

    std::cout << "Running SSL server...\n";
    while (1)
    {
      if (server.poll_listen(100))
        server.recv_client(chunked_cb);
      server.refresh_clients();
    }
  }

  catch (const char e[]) {
    std::cout << std::string(e) << std::endl;
  }

  return 0;
}
