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
#include <vector>
#include <array>
#include <functional>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <regex>
#include <list>
#include <future>
#include <poll.h>
#include <unistd.h>

enum Req { GET, POST, PUT, DELETE };

namespace sockpp
{
  using Cb = std::function<void(const std::string &)>;
  const Cb ident_cb { [](const std::string &) { } };

  class Http
  {
  protected:
    int sockfd { -1 };
    struct ::pollfd pollfd { };
  public:
    Http(void) = default;
    Http(const int sockfd) : sockfd { sockfd } { };
    ~Http(void) { deinit(); }
    bool init_client(const char [], const char []);
    bool init_server(const char []);
    void deinit(void) { ::close(sockfd); }
    void init_poll(void);
    virtual bool poll(const int);
    bool pollin(void);
    bool pollerr(void);
    virtual bool connect(const char []);
    virtual bool read(char &);
    virtual bool write(const std::string &);
    ////////////////////
    int accept(void);
    //bool bind(void);
    //bool listen(void);
  };

  class InitHttps
  {
  protected:
    static ::SSL_CTX *client, *server;
  public:
    InitHttps(void);
    static void init(void);
  };

  class Https : private InitHttps, public Http
  {
    //::SSL_CTX *ctx { nullptr };
    ::BIO *r { BIO_new(BIO_s_mem()) }, *s { nullptr };
    ::SSL *ssl { nullptr };
    //bool ssl_error { false };
  public:
    //Https(const ::SSL_METHOD * = ::TLS_client_method()) noexcept;
    //Https(const int, const ::SSL_METHOD * = ::TLS_server_method()) noexcept;
    Https(void) noexcept;
    Https(const int) noexcept;
    ~Https(void);
    bool configure_context(const std::string &, const std::string &);
    bool set_hostname(const char []);
////////
    bool set_fd(void);
    bool connect(const char []) override;
    bool poll(const int) override;
    bool read(char &) override;
    bool write(const std::string &) override;
    bool clear(void);
////////
    bool accept(void);
    //::SSL_CTX *ssl_ctx(::SSL_CTX *);
    //::SSL_CTX *ssl_ctx(void) { return ctx; }
    int error(int);
    void certinfo(std::string &, std::string &, std::string &);
  };
  
  template<typename S>
  class Recv
  {
    S &sock;
    const std::regex ok_regex { std::regex("OK", std::regex_constants::icase) },
      content_length_regex { std::regex("Content-Length: ", std::regex_constants::icase) },
      transfer_encoding_regex { std::regex("Transfer-Encoding: ", std::regex_constants::icase) },
      chunked_regex { std::regex("Chunked", std::regex_constants::icase) };
  public:
    Recv(S &sock) : sock { sock } { }
    bool is_chunked(const std::string &);
    bool req_header(std::string &);
    void req_body(std::string &, const std::string &);
    void req_body(const Cb &);
    void req_raw(const Cb &);
  };

  struct XHandle
  {
    const Cb cb { ident_cb };
    const Req req { GET };
    const std::vector<std::string> HEAD;
    const std::string data, endp { "/" };
    std::string header, body;
    XHandle(void) = default;
    /*
    XHandle(decltype(endp) &endp) : 
      endp { endp } { }
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
      */
  };

  template<typename S>
  class Client
  {
    S sock;
    const std::string host;
    const char *AGENT { "TCPRequest" };
    char httpver[8] { };
  public:
    Client(const float, const std::string &, const std::string &);
    bool sendreq(const Req, const std::vector<std::string> &, const std::string &, const std::string &);
    bool performreq(XHandle &);
    void close(void) { sock.deinit(); }
  };

  template<typename S>
  class Multi
  {
    const std::vector<std::reference_wrapper<Client<S>>> C;
  public:
    Multi(const std::vector<std::reference_wrapper<Client<S>>> &);
    void performreq(const std::vector<std::reference_wrapper<XHandle>> &);
  };
  
  template<typename S>
  class Server
  {
    S sock;
    //const std::string host;
    std::list<std::future<void>> F;
  public:
    Server(const char []);
    bool poll_listen(const int timeout_ms) { return sock.poll(timeout_ms); }
    void recv_client(const std::function<void(S &)> &, const std::string & = "/tmp/cert.pem", const std::string & = "/tmp/key.pem");
    void refresh_clients(void);
  };
}
