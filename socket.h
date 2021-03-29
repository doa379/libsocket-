#pragma once

#include <string>
#include <netinet/in.h>
//#include <arpa/inet.h>
#include <vector>

enum REQUEST { GET, POST, PUT, DELETE };

class ClientSocket
{
  char http_ver[4];
  int sd;
  struct sockaddr_in sa;
  std::string report, hostname, agent { "HttpRequest" };
public:
  ClientSocket(const float);
  ~ClientSocket(void);
  bool connect(const std::string &, const unsigned);
  bool recvreq(char *, size_t);
  bool sendreq(REQUEST, const std::string &, const std::vector<std::string> &, const std::string &);
  std::string &get_report(void);
  ////////////////////////////////
  int get_sd(void) { return sd; };
};

class ServerSocket
{

public:
};

class SSL
{

public:
};

class SSLClientSocket
{

public:
};

class SSLServerSocket
{

public:
};
