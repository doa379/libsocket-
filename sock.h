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
#include <regex>
#include <list>
#include <future>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <poll.h>
#include <unistd.h>

enum Req { GET, POST, PUT, DELETE };
const char CERT[] { "/tmp/cert.pem" };
const char KEY[] { "/tmp/key.pem" };

namespace sockpp
{
  using Cb = std::function<void(const std::string &)>;
  const Cb ident_cb { [](const std::string &) { } };

  class Http
  {
    char p { };
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
    bool pollin(const int);
    bool pollerr(const int);
    int accept(void) { return ::accept(sockfd, nullptr, nullptr); }
    bool read(char &);
    virtual void connect(const char []) { }
    virtual void readfilter(char p) { this->p = p; }
    virtual bool postread(char &p) { p = this->p; this->p = '\0'; return p; }
    virtual bool write(const std::string &);
  };

  class InitHttps
  {
  protected:
  public:
    InitHttps(void);
    static void init(void);
  };

  class Https : private InitHttps, public Http
  {
    ::SSL_CTX *ctx { nullptr };
    ::SSL *ssl { nullptr };
    ::BIO *r { nullptr }, *w { nullptr };
  public:
    Https(void) { }
    Https(const int sockfd) : Http { sockfd } { }
    ~Https(void) { deinit(); }
    void init_client(void) { ctx = ::SSL_CTX_new(::TLS_client_method()); }
    void init_server(void) { ctx = ::SSL_CTX_new(::TLS_server_method()); }
    void init(void) { ssl = ::SSL_new(ctx); }
    void deinit(void);
    bool configure_ctx(const char [], const char []);
    ::SSL_CTX *set_ctx(::SSL_CTX *ctx) { return ::SSL_set_SSL_CTX(ssl, ctx); }
    ::SSL_CTX *get_ctx(void) { return ctx; }
    void init_rbio(void) { r = ::BIO_new(::BIO_s_mem()); }
    void init_wbio(void) { w = ::BIO_new(::BIO_s_mem()); }
    void set_rwbio(void) { ::SSL_set_bio(ssl, r, w); }
    void set_connect_state(void) { ::SSL_set_connect_state(ssl); }
    void set_accept_state(void) { ::SSL_set_accept_state(ssl); }
    void set_hostname(const char HOST[]) { ::SSL_set_tlsext_host_name(ssl, HOST); }
    void set_fd(int sockfd) { ::SSL_set_fd(ssl, sockfd); }
    void do_handshake(void) { ::SSL_do_handshake(ssl); }
    void certinfo(std::string &, std::string &, std::string &);
    void connect(const char []) override;
    void readfilter(char) override;
    bool postread(char &) override;
    bool write(const std::string &) override;
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
    std::size_t parse_cl(const std::string &);
    bool req_body(std::string &, const std::size_t);
    bool req_body(const Cb &);
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
  };

  template<typename S>
  class Client
  {
    S sock;
    const std::string host;
    const char *AGENT { "TCPRequest" };
    char httpver[8] { };
  public:
    Client(const float, const char [], const char []);
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
    const std::string host;
    std::list<std::future<void>> F;
  public:
    Server(const char []);
    bool poll_listen(const int timeout_ms) { return sock.pollin(timeout_ms); }
    void recv_client(const std::function<void(S &)> &, const char [] = CERT, const char [] = KEY);
    void refresh_clients(void);
  };
}
