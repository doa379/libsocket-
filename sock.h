/**********************************************************************************
MIT License

Copyright (c) 2021 doa379

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
**********************************************************************************/

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
enum Req { GET, POST, PUT, DELETE };
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
  virtual bool connect(const std::string & = { });
  virtual bool read(char &);
  virtual bool write(const std::string &);
  int accept(void);
  bool bind(void);
  bool listen(void);
};

class InitSSock
{
public:
  InitSSock(void);
  static void init(void);
};

class SSock : private InitSSock, public Sock
{
  SSL_CTX *ctx { nullptr };
  SSL *ssl { nullptr };
public:
  SSock(const SSL_METHOD *, const unsigned = 0);
  ~SSock(void);
  bool configure_context(const std::string &, const std::string &);
  bool set_hostname(const std::string &);
  bool set_fd(void);
  bool connect(const std::string &) override;
  bool read(char &) override;
  bool write(const std::string &) override;
  bool clear(void);
  bool accept(void);
  SSL_CTX *ssl_ctx(SSL_CTX *);
  SSL_CTX *ssl_ctx(void) { return ctx; }
  int error(int);
  void certinfo(std::string &, std::string &, std::string &);
};

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
  bool req(T &, const Cb & = dummy_cb);
  template<typename T>
  void req_raw(T &, const Cb &);
  std::string &header(void) { return _header; }
  std::string &body(void) { return _body; }
  void clear_header(void) { _header.clear(); }
  void clear_body(void) { _body.clear(); }
  void set_timeout(const unsigned timeout_ms) { this->timeout_ms = timeout_ms; }
};

template<typename T>
class MultiClient;

template<typename T>
class Client
{
  friend class MultiClient<T>;
  float httpver;
  std::string hostname;
  unsigned port;
  std::unique_ptr<T> sock;
  const std::string_view agent { "HttpRequest" };
  Recv recv;
public:
  Client(const float, const std::string &, const unsigned);
  void init_sock(void);
  bool connect(void);
  bool sendreq(const std::vector<std::string> & = { }, const std::string & = { });
  bool sendreq(const Req, const std::string & = "/", const std::vector<std::string> & = { }, const std::string & = { });
  bool performreq(const Cb & = dummy_cb, const std::vector<std::string> & = { }, const std::string & = { });
  bool performreq(const Req, const Cb & = dummy_cb, const std::string & = "/", const std::vector<std::string> & = { }, const std::string & = { });
  bool recvreq(const Cb &cb = dummy_cb) { return recv.req(*sock, cb); }
  void recvreq_raw(const Cb &cb) { recv.req_raw<T>(*sock, cb); }
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
  bool reg_client(Client<T> &);
  bool connect(void);
  void recvreq(unsigned, const std::vector<Cb> & = { });
  decltype(C) &clients(void) { return C; }
};

template<typename T>
class Server
{
protected:
  std::string hostname;
  unsigned port;
  std::unique_ptr<T> sock;
  struct pollfd listensd { };
  std::list<std::future<void>> C;
public:
  Server(const std::string &, const unsigned);
  void init_sock(void);
  bool connect(void);
  bool poll_listen(unsigned);
  std::shared_ptr<T> recv_client(const std::string & = CERTPEM, const std::string & = KEYPEM);
  void new_client(std::shared_ptr<T>, const std::function<void(T &)> &);
  void refresh_clients(void);
};
