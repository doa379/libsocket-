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
  std::string hostname, agent { "HttpRequest" }, report, response_body, response_header;
public:
  ClientSocket(const float);
  ~ClientSocket(void);
  bool connect(const std::string &, const unsigned);
  bool recvreq(void);
  bool sendreq(REQUEST, const std::string &, const std::vector<std::string> &, const std::string &);
  std::string &get_report(void) { return report; };
  std::string &get_response(void) { return response_body; };
  std::string &get_header(void) { return response_header; };
};

class ServerSocket
{
public:
  ServerSocket(void);
  ~ServerSocket(void);
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
