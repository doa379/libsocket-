#pragma once

#include <string>
#include <netinet/in.h>
#include <vector>
#include <functional>
#include <openssl/ssl.h>
#include <regex>
#include <chrono>

static const float DEFAULT_HTTPVER { 2.0 };
static const std::string CERTPEM { "/tmp/cert.pem" };
static const std::string KEYPEM { "/tmp/key.pem" };
static const unsigned MAX_CLIENTS { 256 };
static const unsigned WAITMS { 100 };
static const unsigned DEFAULT_TIMEOUT { 30 * 1000 };

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

using time_p = std::chrono::time_point<std::chrono::system_clock>;

template<typename T>
class Time
{
protected:
  unsigned timeout { DEFAULT_TIMEOUT };
public:
  time_p now(void) noexcept { return std::chrono::system_clock::now(); };
  std::size_t difftime(time_p t1, time_p t0)
  {
    return std::chrono::duration_cast<T>(t1.time_since_epoch()).count() -
      std::chrono::duration_cast<T>(t0.time_since_epoch()).count();
  }
  void set_timeout(const unsigned timeout) { this->timeout = timeout; };
};

using Cb = std::function<void(const std::string &)>;

class Client : public Http, public Time<std::chrono::milliseconds>
{
  friend class MultiClient;
  std::string agent { "HttpRequest" }, response_header, response_body;
  std::smatch match;
  const std::regex content_length_regex { std::regex("Content-Length: ", std::regex_constants::icase) };
  Cb response_cb { [](const std::string &) { } };
public:
  Client(const float, const std::string &, const unsigned);
  ~Client(void);
  bool connect(void);
  bool sendreq(const std::vector<std::string> &, const std::string &);
  bool sendreq(REQUEST, const std::string &, const std::vector<std::string> &, const std::string &);
  void recvreq(void);
  void recvreq_raw(void);
  std::string &get_response(void) { return response_body; };
  std::string &get_header(void) { return response_header; };
  void set_cb(const decltype(response_cb) &callback) { response_cb = callback; };
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
  void recvreq(void);
};

class Server : public Http
{
protected:
public:
  Server(const float, const std::string &, const unsigned);
  bool connect(void);
  virtual bool run(const std::function<void(const int)> &) = 0;
};

class HttpServer : public Server
{
public:
  HttpServer(const std::string &, const unsigned);
  ~HttpServer(void);
  bool write(const int, const std::string &);
  bool run(const std::function<void(const int)> &);
};

class HttpsServer : public Server
{
  SecureServerPair sslserver;
public:
  HttpsServer(const std::string &, const unsigned);
  ~HttpsServer(void);
  bool run(const std::function<void(const int)> &);
};
