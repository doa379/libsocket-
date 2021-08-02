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
static const unsigned DEFAULT_TIMEOUTMS { 15 * 1000 };
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
  unsigned timeout_ms { };
  Time time;
  std::string _header, _body;
  std::smatch match;
  const std::regex ok_regex { std::regex("OK", std::regex_constants::icase) },
    content_length_regex { std::regex("Content-Length: ", std::regex_constants::icase) },
    transfer_encoding_regex { std::regex("Transfer-Encoding: ", std::regex_constants::icase) },
    chunked_regex { std::regex("Chunked", std::regex_constants::icase) };
public:
  Recv(const unsigned);
  template<typename S>
  bool req(S &, const Cb & = dummy_cb);
  template<typename S>
  void req_raw(S &, const Cb &);
  std::string &header(void) { return _header; }
  std::string &body(void) { return _body; }
  void clear_header(void) { _header.clear(); }
  void clear_body(void) { _body.clear(); }
  void timeout(const unsigned timeout) { timeout_ms = timeout; }
};

template<typename S>
class MultiSync;

template<typename S>
class MultiAsync;

template<typename S>
class Client
{
  friend class MultiSync<S>;
  friend class MultiAsync<S>;
  float httpver;
  std::string hostname;
  unsigned port;
  std::unique_ptr<Recv> recv;
  std::unique_ptr<S> sock;
  const std::string_view agent { "HttpRequest" };
public:
  Client(const float, const std::string &, const unsigned, const unsigned = DEFAULT_TIMEOUTMS);
  void init_sock(void);
  bool connect(void);
  bool sendreq(const std::vector<std::string> & = { }, const std::string & = { });
  bool sendreq(const Req, const std::string & = "/", const std::vector<std::string> & = { }, const std::string & = { });
  bool performreq(const Cb & = dummy_cb, const std::vector<std::string> & = { }, const std::string & = { });
  bool performreq(const Req, const Cb & = dummy_cb, const std::string & = "/", const std::vector<std::string> & = { }, const std::string & = { });
  bool recvreq(const Cb &cb = dummy_cb) { return recv->req(*sock, cb); }
  void recvreq_raw(const Cb &cb) { recv->req_raw(*sock, cb); }
  std::string &header(void) { return recv->header(); }
  std::string &body(void) { return recv->body(); }
  void timeout(const unsigned timeout) { recv->timeout(timeout); }
};

template<typename S>
class MultiSync
{
  std::vector<std::reference_wrapper<Client<S>>> C;
  Time time;
  unsigned timeout;
public:
  MultiSync(void) { }
  MultiSync(const std::vector<std::reference_wrapper<Client<S>>> &);
  bool reg_client(Client<S> &);
  unsigned connect(void);
  template<typename T>
  void recvreq(const unsigned, const std::vector<Cb> & = { });
  decltype(C) &clients(void) { return C; }
};

template<typename S>
struct ClientHandle
{
  Client<S> &c;
  const Cb &cb;
  const Req req;
  const std::string endp, data;
  const std::vector<std::string> HEADERS;
};

template<typename S>
class MultiAsync
{
  const std::vector<ClientHandle<S>> &H;
  Time time;
  unsigned timeout;
public:
  MultiAsync(const std::vector<ClientHandle<S>> &);
  unsigned connect(void);
  void performreq(const unsigned, const unsigned);
};

template<typename S>
class Server
{
protected:
  std::string hostname;
  unsigned port;
  std::unique_ptr<S> sock;
  struct pollfd listensd { };
  std::list<std::future<void>> C;
public:
  Server(const std::string &, const unsigned);
  void init_sock(void);
  bool connect(void);
  bool poll_listen(unsigned);
  std::shared_ptr<S> recv_client(const std::string & = CERTPEM, const std::string & = KEYPEM);
  void new_client(std::shared_ptr<S>, const std::function<void(S &)> &);
  void refresh_clients(void);
};
