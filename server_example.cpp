#include <iostream>
#include <random>
#include <thread>
#include "socket.h"

static const std::string host0 { "localhost" };
static const unsigned port0 { 8080 };

int rand(std::size_t a, std::size_t b)
{
  std::random_device dev;
  std::mt19937 rng(dev());
  std::uniform_int_distribution<std::mt19937::result_type> dist(a, b);
  return dist(rng);
}

std::string to_base16(std::size_t arg)
{
  std::stringstream stream;
  stream << std::hex << arg;
  return "0x" + stream.str();
}

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

  HttpServer server(hostname, port_no);
  if (!server.connect())
  {
    std::cout << server.get_report() << std::endl;
    return 1;
  }

  auto cb { 
    [&](const int clientsd) {
      const std::string header { 
        "HTTP/1.1 Stream\r\n" + 
        hostname + ":" + std::to_string(port_no) + "\r\n\r\n" };
      if (!server.write(clientsd, header))
        return;
      std::string document;
      while (1)
      {
        auto s { std::to_string(pow(2, rand(8, 32))) };
        std::cout << s << std::endl;
        document = to_base16(s.size() + 2) + "\r\n" + s + "\r\n";
        if (!server.write(clientsd, document))
          break;
        std::this_thread::sleep_for(std::chrono::milliseconds(rand(500, 2000)));
      }
    } 
  };

  std::cout << "Running server...\n";
  server.run(cb);
  return 0;
}
