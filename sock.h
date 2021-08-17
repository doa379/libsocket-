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
static const char CERTPEM[] { "/tmp/cert.pem" };
static const char KEYPEM[] { "/tmp/key.pem" };
static const std::array<std::string, 4> REQ { "GET", "POST", "PUT", "DELETE" };
enum Req { GET, POST, PUT, DELETE };

namespace sockpp
{
  using Cb = std::function<void(const std::string &)>;
  const Cb ident_cb { [](const std::string &) { } };

  class Http
  {
  protected:
    int sd;
    struct sockaddr_in sa;
  public:
    Http(const int = { });
    ~Http(void);
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
    int desc(void) { return sd; }
  };

  class InitHttps
  {
  public:
    InitHttps(void);
    static void init(void);
  };
  
  class Https : private InitHttps, public Http
  {
    SSL_CTX *ctx { nullptr };
    SSL *ssl { nullptr };
  public:
    Https(const int, const SSL_METHOD *) noexcept;
    ~Https(void);
    bool configure_context(const std::string &, const std::string &);
    bool set_hostname(const std::string &);
////////
    bool set_fd(void);
    bool connect(const std::string &) override;
    bool read(char &) override;
    bool write(const std::string &) override;
    bool clear(void);
////////
    bool accept(void);
    SSL_CTX *ssl_ctx(SSL_CTX *);
    SSL_CTX *ssl_ctx(void) { return ctx; }
    int error(int);
    void certinfo(std::string &, std::string &, std::string &);
  };

  class HttpsCli : public Https
  { 
  public:
    HttpsCli(const int sd = { }) : Https { sd, TLS_client_method() } { }
  };
  
  class HttpsSvr : public Https
  {
  public:
    HttpsSvr(const int sd = { }) : Https { sd, TLS_server_method() } { }
  };

  class Recv
  {
    Time time;
    char p;
    std::smatch match;
    const std::regex ok_regex { std::regex("OK", std::regex_constants::icase) },
      content_length_regex { std::regex("Content-Length: ", std::regex_constants::icase) },
      transfer_encoding_regex { std::regex("Transfer-Encoding: ", std::regex_constants::icase) },
      chunked_regex { std::regex("Chunked", std::regex_constants::icase) };
  public:
    template<typename S>
    bool req_header(std::string &, S &);
    bool is_chunked(const std::string &);
    template<typename S>
    void req_body(std::string &, const std::string &, S &);
    template<typename T, typename S>
    void req_body(const unsigned, const Cb &, S &);
    template<typename T, typename S>
    void req_raw(const unsigned, const Cb &, S &);
  };

  struct XHandle
  {
    const Cb cb { ident_cb };
    const Req req { GET };
    const std::vector<std::string> HEAD;
    const std::string data, endp;
    std::string header, body;
    XHandle(void) : cb { ident_cb }, req { GET }, endp { "/" } { }
    XHandle(const Req req, decltype(HEAD) &HEAD, decltype(data) &data, decltype(endp) &endp = "/") : 
      req { req }, HEAD { HEAD }, data { data }, endp { endp } { }
    XHandle(const Cb &cb, const Req req, decltype(HEAD) &HEAD, decltype(data) &data, decltype(endp) &endp = "/") : 
      cb { cb }, req { req }, HEAD { HEAD }, data { data }, endp { endp } { }
    XHandle(decltype(HEAD) &HEAD, decltype(endp) &endp = "/") : 
      HEAD { HEAD }, endp { endp } { }
    XHandle(const Cb &cb, decltype(HEAD) &HEAD, decltype(endp) &endp = "/") : 
      cb { cb }, HEAD { HEAD }, endp { endp } { }
    XHandle(const Cb &cb, decltype(endp) &endp = "/") : 
      cb { cb }, endp { endp } { }
  };

  template<typename S>
  class Client
  {
    S sock;
    std::string hostname;
    unsigned port;
    char httpver[8];
    const std::string_view agent { "HttpRequest" };
  public:
    Client(const float, const std::string &, const unsigned);
    bool connect(void);
    bool sendreq(const Req, const std::vector<std::string> &, const std::string &, const std::string &);
    template<typename T>
    bool performreq(const unsigned, XHandle &);
    void close(void) { sock.deinit(); }
    int sd(void) { return sock.desc(); }
  };

  template<typename S>
  class Multi
  {
    std::vector<std::reference_wrapper<Client<S>>> C;
    Time time;
  public:
    Multi(const std::vector<std::reference_wrapper<Client<S>>> &);
    unsigned connect(void);
    template<typename T>
    void performreq(const unsigned, const std::vector<std::reference_wrapper<XHandle>> &);
    template<typename T>
    void performreq(const unsigned, const std::size_t, const std::vector<std::reference_wrapper<XHandle>> &);
  };
  
  template<typename S>
  class Server
  {
    S sock;
    std::string hostname;
    unsigned port;
    struct pollfd listensd { };
    std::list<std::future<void>> C;
  public:
    Server(const std::string &, const unsigned);
    bool connect(void);
    bool poll_listen(unsigned);
    std::shared_ptr<S> recv_client(const std::string & = CERTPEM, const std::string & = KEYPEM);
    void new_client(std::shared_ptr<S>, const std::function<void(S &)> &);
    void refresh_clients(void);
  };
}
