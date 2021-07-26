#pragma once

#include <string>
#include <string_view>
#include <netinet/in.h>
#include <vector>
#include <array>
#include <functional>
#include <openssl/ssl.h>
#include <regex>
#include <list>
#include <future>
#include <memory>
#include <poll.h>
#include "time.h"

static const float DEFAULT_HTTPVER { 2.0 };
static const unsigned DEFAULT_TIMEOUTMS { 30 * 1000 };
static const char CERTPEM[] { "/tmp/cert.pem" };
static const char KEYPEM[] { "/tmp/key.pem" };
static const unsigned MAX_CLIENTS { 256 };
static const std::array<std::string, 4> REQ { "GET", "POST", "PUT", "DELETE" };
enum { GET, POST, PUT, DELETE };
using Cb = std::function<void(const std::string &)>;
static const Cb dummy_cb { [](const std::string &) { } };

class Sock
{
protected:
  int sd;
  struct sockaddr_in sa;
public:
  Sock(const int = 0);
  ~Sock(void);
  const int get(void) { return sd; }
  bool init(const int);
  void deinit(void);
  bool init_connect(const std::string &, const unsigned);
  virtual bool connect(void);
  virtual bool read(char &);
  virtual bool write(const std::string &);
  int accept(void);
  bool bind(void);
  bool listen(void);
};

class InitSocks
{
public:
  InitSocks(void);
  static void init(void);
};

class Socks : private InitSocks, public Sock
{
  SSL_CTX *ctx { nullptr };
  SSL *ssl { nullptr };
  std::string hostname, certpem, keypem;
public:
  Socks(const SSL_METHOD *, const std::string &, const std::string &, const std::string &, const unsigned = 0);
  ~Socks(void);
  bool configure_context(void);
  bool set_hostname(void);
  bool set_fd(void);
  bool connect(void) override;
  bool read(char &) override;
  bool write(const std::string &) override;
  bool clear(void);
  bool accept(void);
  SSL_CTX *set_ctx(SSL_CTX *);
  SSL_CTX *get_ctx(void) { return ctx; }
};
/*
class InitSSL
{
public:
  InitSSL(void);
  static void init(void);
};

class Secure : private InitSSL
{
protected:
  SSL_CTX *ctx { nullptr };
  SSL *ssl { nullptr };
  std::string _cipherinfo, _certificate, _issuer;
public:
  Secure(const SSL_METHOD *);
  ~Secure(void);
  int set_fd(const int);
  int connect(void);
  int write(const std::string &);
  int error(int);
  int clear(void);
  void gather_certificate(std::string &);
  std::string &cipherinfo(void) { return _cipherinfo; }
  std::string &certificate(void) { return _certificate; }
  std::string &issuer(void) { return _issuer; }
};

class SecureClient : public Secure
{
public:
  SecureClient(void);
  bool configure_context(std::string &, const std::string &, const std::string &);
  int set_tlsext_hostname(const std::string &);
  int read(void *, int);
  SSL_CTX *ctx(void) { return Secure::ctx; }
};

class SecureServer : public Secure
{
public:
  SecureServer(void);
  SSL_CTX *set_CTX(SSL_CTX *);
  int accept(void);
};
*/
class Recv
{
  Time time;
  unsigned timeout_ms { DEFAULT_TIMEOUTMS };
  std::string _header, _body;
  std::smatch match;
  const std::regex ok_regex { std::regex("OK", std::regex_constants::icase) },
    content_length_regex { std::regex("Content-Length: ", std::regex_constants::icase) },
    transfer_encoding_regex { std::regex("Transfer-Encoding: ", std::regex_constants::icase) },
    chunked_regex { std::regex("Chunked", std::regex_constants::icase) };
public:
  template<typename T>
  bool req(T &, const Cb &);
  template<typename T>
  void req_raw(T &, const Cb &);
  std::string &header(void) { return _header; }
  std::string &body(void) { return _body; }
  void clear_header(void) { _header.clear(); }
  void clear_body(void) { _body.clear(); }
  void set_timeout(const unsigned timeout_ms) { this->timeout_ms = timeout_ms; }
  //bool close_client(int);
};

template<typename T>
class MultiClient;

template<typename T>
class Client
{
  friend class MultiClient<T>;
  std::unique_ptr<T> sock;
  std::string hostname;
  unsigned port;
  char httpver[8];
  const std::string_view agent { "HttpRequest" };
  Recv recv;
public:
  Client(const float, const std::string &, const unsigned, const std::string & = CERTPEM, const std::string & = KEYPEM);
  bool connect(void);
  bool sendreq(const std::vector<std::string> & = { }, const std::string & = { });
  bool sendreq(const unsigned, const std::string & = "/", const std::vector<std::string> & = { }, const std::string & = { });
  bool performreq(const Cb & = dummy_cb, const std::vector<std::string> & = { }, const std::string & = { });
  bool performreq(const unsigned, const Cb & = dummy_cb, const std::string & = "/", const std::vector<std::string> & = { }, const std::string & = { });
  bool req(const Cb &cb = dummy_cb) { return recv.req(*sock, cb); }
  void req_raw(const Cb &cb = dummy_cb) { recv.req_raw(*sock, cb); }
  std::string &header(void) { return recv.header(); }
  std::string &body(void) { return recv.body(); }
  void set_timeout(const unsigned timeout_ms) { recv.set_timeout(timeout_ms); }
};

template<typename T>
class MultiClient
{
  Time time;
  unsigned timeout;
  std::vector<std::reference_wrapper<Client<T>>> C;
public:
  bool set_client(Client<T> &);
  bool connect(void);
  void recvreq(unsigned);
  decltype(C) &clients(void) { return C; }
};

template<typename T>
class Server
{
protected:
  std::unique_ptr<T> sock;
  std::string hostname;
  unsigned port;
  struct pollfd listensd { };
  std::list<std::future<void>> C;
public:
  Server(const std::string &, const unsigned, const std::string & = CERTPEM, const std::string & = KEYPEM);
  bool connect(void);
  bool poll_listen(unsigned);
  std::shared_ptr<T> recv_client(const std::string & = CERTPEM, const std::string & = KEYPEM);
  void new_client(std::shared_ptr<T>, const std::function<void(T &)> &);
  void refresh_clients(void);
  //bool close_client(int);
};

/*
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
  SecurePair recv_client(std::string &, const std::string & = CERTPEM, const std::string & = KEYPEM);
};
*/
