#pragma once

#include <string>
#include <netinet/in.h>
#include <vector>
#include <functional>
#include <openssl/ssl.h>

static const float DEFAULT_HTTPVER { 2.0 };

enum REQUEST { GET, POST, PUT, DELETE };

class Http
{
//  friend class Secure;
protected:
  int sd;
  struct sockaddr_in sa;
  char httpver[4];
  std::string hostname, report;
  std::function<bool(void)> connector;
  std::function<bool(char &)> reader;
  std::function<bool(const std::string &)> writer;
public:
  Http(const float);
  ~Http(void);
  std::string &get_report(void) { return report; };
  bool init_connect(const std::string &, const unsigned);
};

class Client : public Http
{
  std::string agent { "HttpRequest" }, response_body, response_header;
public:
  Client(const float);
  ~Client(void);
  bool connect(const std::string &, const unsigned);
  bool recvreq(void);
  bool sendreq(REQUEST, const std::string &, const std::vector<std::string> &, const std::string &);
  std::string &get_response(void) { return response_body; };
  std::string &get_header(void) { return response_header; };
};

class HttpClient : public Client
{
public:
  HttpClient(const float);
  ~HttpClient(void);
};

class HttpServer : public Http
{
  bool is_running;
public:
  HttpServer(void);
  ~HttpServer(void);
  bool connect(const std::string &, const unsigned);
  bool run(const std::string &);
  void stop(void) { is_running = 0; };
};

class Secure
{
  //const SSL_METHOD *meth { TLS_client_method() };
  SSL_CTX *ctx;
protected:
  SSL *ssl;
  char err[128];
public:
  Secure(void);
  ~Secure(void);
};

class HttpsClient : public Client, public Secure
{
public:
  HttpsClient(const float);
  ~HttpsClient(void);
};

class HttpsServer
{

public:
};
