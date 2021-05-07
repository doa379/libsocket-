#include <iostream>
#include <random>
#include <thread>
#include <chrono>
#include "socket.h"

static const std::string host0 { "localhost" };
static const unsigned port0 { 8080 };
static const std::string host1 { "..." };
static const unsigned port1 { 8080 };

int rand(int a, int b)
{
  std::random_device dev;
  std::mt19937 rng(dev());
  std::uniform_int_distribution<std::mt19937::result_type> dist(a, b);
  return dist(rng);
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

  const std::string document { "Document being served at " +
    hostname + " port " + std::to_string(port_no) + '\n' },
        header { "Content-Length: " + std::to_string(document.size()) +
          "\r\n\r\n" };

  auto cb { 
    [&](std::string &res) {
      res = header + document;
      while (1)
      {
        std::string s { std::to_string(rand(100, 999)) };
        res = std::to_string(s.size()) + "\r\n" + s + "\r\n\r\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
      }
    } 
  };

  server.run(cb);
  return 0;
}
