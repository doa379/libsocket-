#pragma once

#include <string>
#include <netinet/in.h>
//#include <arpa/inet.h>
#include <vector>

static const float DEFAULT_HTTPVER { 2.0 };

enum REQUEST { GET, POST, PUT, DELETE };

class Http
{
protected:
  int sd;
  struct sockaddr_in sa;
  char httpver[4];
  std::string hostname, report;
public:
  Http(const float);
  ~Http(void);
  std::string &get_report(void) { return report; };
  bool init_connect(const std::string &, const unsigned);
};

class HttpClient : public Http
{
  std::string agent { "HttpRequest" }, response_body, response_header;
public:
  HttpClient(const float);
  ~HttpClient(void);
  bool connect(const std::string &, const unsigned);
  bool recvreq(void);
  bool sendreq(REQUEST, const std::string &, const std::vector<std::string> &, const std::string &);
  std::string &get_response(void) { return response_body; };
  std::string &get_header(void) { return response_header; };
};

class HttpServer : public Http
{
public:
  HttpServer(void);
  ~HttpServer(void);
  bool connect(const std::string &, const unsigned);
  bool run(void);
};

class SSL
{

public:
};

class HttpsClient
{
public:
};

class HttpsServer
{

public:
};
