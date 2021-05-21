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

enum REQUEST { GET, POST, PUT, DELETE };

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
public:
  Http(const float, const std::string &hostname, const unsigned port);
  ~Http(void);
  std::string &get_report(void) { return report; };
  bool init_connect(void);
};

class Secure
{
protected:
  SSL *ssl { nullptr };
  SSL_CTX *ctx { nullptr };
  std::string certpem, keypem, cipherinfo, certificate, issuer;
public:
  Secure(void);
  Secure(const std::string &);
  Secure(const std::string &, const std::string &);
  void deinit_ssl(void);
  void gather_certificate(void);
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
  std::string &get_cipherinfo(void) { return cipherinfo; };
  std::string &get_certificate(void) { return certificate; };
  std::string &get_issuer(void) { return issuer; };
};

class SecureClientPair : public Secure
{
public:
  SecureClientPair(void);
  ~SecureClientPair(void);
};

class SecureServerPair : public Secure
{
public:
  SecureServerPair(void);
  ~SecureServerPair(void);
};

using Cb = std::function<void(const std::string &)>;

class Client : public Http, public Time<std::chrono::milliseconds>
{
  friend class MultiClient;
  std::string agent { "HttpRequest" }, response_header, response_body;
  std::smatch match;
  const std::regex ok_regex { std::regex("OK", std::regex_constants::icase) },
    content_length_regex { std::regex("Content-Length: ", std::regex_constants::icase) },
    transfer_encoding_regex { std::regex("Transfer-Encoding: ", std::regex_constants::icase) },
    chunked_regex { std::regex("Chunked", std::regex_constants::icase) };
  Cb response_cb { [](const std::string &) { } };
public:
  Client(const float, const std::string &, const unsigned);
  ~Client(void);
  bool connect(void);
  bool sendreq(const std::vector<std::string> &, const std::string &);
  bool sendreq(REQUEST, const std::string &, const std::vector<std::string> &, const std::string &);
  bool recvreq(void);
  void recvreq_raw(void);
  bool performreq(const std::vector<std::string> &, const std::string &);
  bool performreq(REQUEST, const std::string &, const std::vector<std::string> &, const std::string &);
  std::string &get_response(void) { return response_body; };
  std::string &get_header(void) { return response_header; };
  void set_cb(const decltype(response_cb) &callback) { response_cb = callback; };
  void set_timeout(const unsigned timeout) { this->timeout = timeout; };
  void clear_buffer(void) { response_body.clear(); };
};

class HttpClient : public Client
{
public:
  HttpClient(const float, const std::string &, const unsigned); 
  ~HttpClient(void);
};

class HttpsClient : public Client
{
  SecureClientPair sslclient;
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
  void close_client(int);
  void recvreq(std::string &, int);
};

class HttpServer : public Server
{
public:
  HttpServer(const std::string &, const unsigned);
  ~HttpServer(void);
  bool write(const int, const std::string &);
};

struct LocalSecureClient
{
  int clientsd;
  std::shared_ptr<SecureServerPair> sslserver;
};

class HttpsServer : public Server
{
public:
  HttpsServer(const std::string &, const unsigned);
  ~HttpsServer(void);
  LocalSecureClient recv_client(void);
};
