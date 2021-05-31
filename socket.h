#pragma once

#include <string>
#include <netinet/in.h>
#include <vector>
#include <functional>
#include <openssl/ssl.h>
#include <regex>
#include <any>
#include <list>
#include <future>
#include <memory>
#include <sys/poll.h>
#include "time.h"

static const float DEFAULT_HTTPVER { 2.0 };
static const std::string CERTPEM { "/tmp/cert.pem" };
static const std::string KEYPEM { "/tmp/key.pem" };
static const unsigned MAX_CLIENTS { 256 };

enum REQ { GET, POST, PUT, DELETE };

class Http
{
protected:
  int sd;
  struct sockaddr_in sa;
  char httpver[8];
  std::string hostname, report;
  unsigned port;
  std::function<bool(void)> connector;
  std::function<bool(char &)> reader;
  std::function<bool(const std::string &)> writer;
  std::smatch match;
  const std::regex content_length_regex { std::regex("Content-Length: ", std::regex_constants::icase) };
public:
  Http(const float, const std::string &hostname, const unsigned port);
  ~Http(void);
  std::string &get_report(void) { return report; }
  bool init_connect(void);
};

class Secure
{
protected:
  SSL *ssl { nullptr };
  SSL_CTX *ctx { nullptr };
  std::string certpem { CERTPEM }, keypem { KEYPEM }, cipherinfo, certificate, issuer;
public:
  Secure(const SSL_METHOD *);
  Secure(const SSL_METHOD *, const std::string &);
  Secure(const SSL_METHOD *, const std::string &, const std::string &);
  ~Secure(void);
  void init_ssl(const SSL_METHOD *);
  void gather_certificate(std::string &);
  bool configure_context(std::string &);
  int set_tlsext_hostname(const std::string &);
  int set_fd(const int);
  int connect(void);
  int get_error(int);
  int read(void *, int);
  int write(const std::string &);
  int accept(void);
  SSL_CTX *set_CTX(const Secure &);
  int clear(void);
  std::string &get_cipherinfo(void) { return cipherinfo; }
  std::string &get_certificate(void) { return certificate; }
  std::string &get_issuer(void) { return issuer; }
};

class SecureClient : public Secure
{
public:
  SecureClient(void);
};

class SecureServer : public Secure
{
public:
  SecureServer(void);
};

using Cb = std::function<void(const std::string &)>;

class Client : public Http, public Time<std::chrono::milliseconds>
{
  friend class MultiClient;
  std::string agent { "HttpRequest" }, response_header, response_body;
  const std::regex ok_regex { std::regex("OK", std::regex_constants::icase) },
    transfer_encoding_regex { std::regex("Transfer-Encoding: ", std::regex_constants::icase) },
    chunked_regex { std::regex("Chunked", std::regex_constants::icase) };
  Cb response_cb { [](const std::string &) { } };
public:
  Client(const float, const std::string &, const unsigned);
  ~Client(void);
  bool connect(void);
  bool sendreq(const std::vector<std::string> &, const std::string &);
  bool sendreq(const REQ, const std::string &, const std::vector<std::string> &, const std::string &);
  bool recvreq(void);
  void recvreq_raw(void);
  bool performreq(const std::vector<std::string> &, const std::string &);
  bool performreq(const REQ, const std::string &, const std::vector<std::string> &, const std::string &);
  std::string &get_response(void) { return response_body; }
  std::string &get_header(void) { return response_header; }
  void set_cb(const decltype(response_cb) &callback) { response_cb = callback; }
  void set_timeout(const unsigned timeout) { this->timeout = timeout; }
  void clear_buffer(void) { response_body.clear(); }
};

class HttpClient : public Client
{
public:
  HttpClient(const float, const std::string &, const unsigned); 
  ~HttpClient(void);
};

class HttpsClient : public Client
{
  SecureClient sslclient;
  ssize_t err;
public:
  HttpsClient(const float, const std::string &, const unsigned); 
  ~HttpsClient(void);
};

class MultiClient : public Time<std::chrono::milliseconds>
{
  std::vector<std::reference_wrapper<Client>> C;
public:
  MultiClient(void);
  bool set_client(Client &);
  bool connect(void);
  void recvreq(unsigned);
};

class Server : public Http
{
protected:
  struct pollfd listensd { };
  std::list<std::future<void>> C;
public:
  Server(const float, const std::string &, const unsigned);
  bool connect(void);
  bool poll_listen(unsigned);
  int recv_client(void);
  void new_client(const std::function<void(const std::any)> &, std::any);
  void refresh_clients(void);
  bool close_client(int);
};

class HttpServer : public Server
{
public:
  HttpServer(const std::string &, const unsigned);
  ~HttpServer(void);
  void recvreq(std::string &, int);
  bool write(const int, const std::string &);
};

struct SecurePair
{
  int clientsd;
  std::unique_ptr<SecureServer> sslserver;
};

class HttpsServer : public Server
{
public:
  HttpsServer(const std::string &, const unsigned);
  ~HttpsServer(void);
  SecurePair recv_client(std::string &);
};
