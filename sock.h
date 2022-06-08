/**********************************************************************************
MIT License

Copyright (c) 2021-22 doa379

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
#include <array>
#include <functional>
#include <regex>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <poll.h>
#include <unistd.h>
#include <vector>
#include <atomic>
#include <bitset>

namespace sockpp {
  static constexpr float DEFAULT_HTTPVER { 2.0 };
  static const unsigned SINGULAR_TIMEOUTMS { 5000 };
  static const unsigned MULTI_TIMEOUTMS { 2500 };
  static const char CERT[] { "/tmp/cert.pem" };
  static const char KEY[] { "/tmp/key.pem" };
  enum class Req { GET, POST, PUT, DELETE };
  using Client_cb = std::function<void(const std::string &)>;
  const Client_cb ident_cb { [](const std::string &) { } };
  template<typename S>
  using Server_cb = std::function<bool(S &)>;

  class Http {
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
    void deinit(void);
    void init_poll(void);
    bool pollin(const int);
    bool pollout(const int);
    bool pollerr(const int);
    int accept(void) { return ::accept(sockfd, nullptr, nullptr); }
    bool read(char &) const;
    virtual bool connect(const char []) { return true; }
    virtual void readfilter(char p) { this->p = p; }
    virtual bool postread(char &p) { p = this->p; this->p = '\0'; return p; }
    virtual bool write(const std::string &) const;
  };

  class InitHttps {
  protected:
  public:
    InitHttps(void) { InitHttps::init(); }
    static void init(void) { ::OpenSSL_add_ssl_algorithms(); }
  };

  class Https : private InitHttps, public Http {
    ::SSL_CTX *ctx { };
    ::SSL *ssl { };
    ::BIO *r { }, *w { };
  public:
    Https(void) = default;
    Https(const int sockfd) : Http { sockfd } { }
    ~Https(void) { deinit(); }
    bool init_client(void) { return (ctx = ::SSL_CTX_new(::TLS_client_method())); }
    bool init_server(void) { return (ctx = ::SSL_CTX_new(::TLS_server_method())); }
    bool init(void) { return (ssl = ::SSL_new(ctx)); }
    void deinit(void) const;
    bool configure_ctx(const char [], const char []) const;
    ::SSL_CTX *set_ctx(::SSL_CTX *ctx) const { return ::SSL_set_SSL_CTX(ssl, ctx); }
    ::SSL_CTX *get_ctx(void) const { return ctx; }
    bool init_rbio(void) { return (r = ::BIO_new(::BIO_s_mem())); }
    bool init_wbio(void) { return (w = ::BIO_new(::BIO_s_mem())); }
    void set_rwbio(void) const { ::SSL_set_bio(ssl, r, w); }
    void set_connect_state(void) const { ::SSL_set_connect_state(ssl); }
    void set_accept_state(void) const { ::SSL_set_accept_state(ssl); }
    bool set_hostname(const char HOST[]) const { return ::SSL_set_tlsext_host_name(ssl, HOST) > -1; }
    bool set_fd(int sockfd) const { return ::SSL_set_fd(ssl, sockfd) > -1; }
    bool do_handshake(void) const { return ::SSL_do_handshake(ssl) > -1; }
    void certinfo(std::string &, std::string &, std::string &) const;
    bool connect(const char []) override;
    void readfilter(char) override;
    bool postread(char &) override;
    bool write(const std::string &) const override;
  };
 
  template<typename S>
  class Send {
    const std::string agent { "TCPRequest" };
    std::string httpver;
  public:
    Send(void) = delete;
    Send(const float);
    bool req(S &, const std::string &, const Req, const std::vector<std::string> &, const std::string &, const std::string &) const;
  };

  template<typename S>
  class Recv {
    const unsigned timeout_ms { SINGULAR_TIMEOUTMS };
    const std::regex ok_regex { std::regex("OK", std::regex_constants::icase) },
      content_length_regex { std::regex("Content-Length: ", std::regex_constants::icase) },
      transfer_encoding_regex { std::regex("Transfer-Encoding: ", std::regex_constants::icase) },
      chunked_regex { std::regex("Chunked", std::regex_constants::icase) };
  public:
    Recv(const unsigned timeout_ms) : timeout_ms { timeout_ms } { }
    bool is_chunked(const std::string &) const;
    bool req_header(S &, std::string &) const;
    std::size_t parse_cl(const std::string &) const;
    bool req_body(S &, std::string &, const std::size_t) const;
    bool req_body(S &s, const Client_cb &cb, std::string &body) const { return req_chunked(s, cb, body); }
    bool req_chunked(S &, const Client_cb &, std::string &) const;
    bool req_chunked_raw(S &, const Client_cb &, std::string &) const;
  };

  struct XHandle {
    const Client_cb cb { ident_cb };
    const Req req { Req::GET };
    const std::vector<std::string> HEAD;
    const std::string data, endp { "/" };
    std::string header, body;
  };

  template<typename S>
  class Client {
    const float ver { DEFAULT_HTTPVER };
    const std::string host;
    S sock;
  public:
    Client(void) = delete;
    Client(const float, const char [], const char []);
    bool performreq(XHandle &, const unsigned = SINGULAR_TIMEOUTMS);
    void close(void) { sock.Http::deinit(); }
  };

  template<typename S>
  class MultiClient {
    static const auto MAX_N { 32 };
    const float ver { DEFAULT_HTTPVER };
    const std::string host;
    std::array<S, MAX_N> SOCK;
    std::bitset<MAX_N> CONN;
  public:
    MultiClient(void) = delete;
    MultiClient(const float, const char [], const char [], const unsigned);
    bool performreq(const std::vector<std::reference_wrapper<XHandle>> &, const unsigned = SINGULAR_TIMEOUTMS);
    decltype(MAX_N) count(void) const { return CONN.count(); }
  };
  
  template<typename S>
  class Server {
    S sock;  // Master
    std::vector<std::unique_ptr<S>> SOCK;  // Slaves
    std::atomic<bool> quit { };
  public:
    Server(void) = delete;
    Server(const char []);
    bool poll_listen(const int timeout_ms) { return sock.pollin(timeout_ms); }
    void recv_client(const char [], const char []);
    void run(const Server_cb<S> &, const char [] = CERT, const char [] = KEY);
    void exit(void) { quit = true; }
  };
}
