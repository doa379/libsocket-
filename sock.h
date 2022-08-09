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
#include <vector>
#include <atomic>
#include <bitset>
#include <regex>
#include <variant>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <poll.h>
#include <unistd.h>

namespace sockpp {
  static constexpr float DEFAULT_HTTPVER { 2.0 };
  // Timeout Milliseconds (TOMS)
  static constexpr unsigned SINGULAR_TOMS { 2000 };
  static constexpr unsigned MULTI_TOMS { 2500 };
  // SSL BIO Buffer Size
  static constexpr unsigned SBN { 16384 };
  static constexpr char CERT[] { "/tmp/cert.pem" };
  static constexpr char KEY[] { "/tmp/key.pem" };

  class Http {
    char p { };
  protected:
    int sockfd { -1 };
    struct ::pollfd pollfd { };
  public:
    Http(void) = default;
    explicit Http(const int FD) : sockfd { FD } { };
    ~Http(void) { deinit(); }
    bool init_client(const char [], const char []);
    bool init_server(const char []);
    void deinit(void);
    void init_poll(void) { pollfd.fd = sockfd; }
    bool pollin(const int);
    bool pollout(const int);
    bool pollerr(const int);
    int accept(void) { return ::accept(sockfd, nullptr, nullptr); }
    bool read(char &p) const {
      return ::read(sockfd, &p, sizeof p) > 0; }
    virtual bool connect(const char []) { return true; }
    virtual void readfilter(char p) { this->p = p; }
    virtual bool postread(char &p) {
      p = this->p; this->p = '\0'; return p; }
    virtual bool write(const std::string &req) const {
      return ::write(sockfd, req.c_str(), req.size()) > 0; }
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
    explicit Https(const int FD) : Http { FD } { }
    ~Https(void) { deinit(); }
    bool init_client(void) {
      return (ctx = ::SSL_CTX_new(::TLS_client_method())); }
    bool init_server(void) {
      return (ctx = ::SSL_CTX_new(::TLS_server_method())); }
    bool init(void) { return (ssl = ::SSL_new(ctx)); }
    void deinit(void) const;
    bool configure_ctx(const char [], const char []) const;
    ::SSL_CTX *set_ctx(::SSL_CTX *ctx) const {
      return ::SSL_set_SSL_CTX(ssl, ctx); }
    ::SSL_CTX *get_ctx(void) const { return ctx; }
    bool init_rbio(void) { return (r = ::BIO_new(::BIO_s_mem())); }
    bool init_wbio(void) { return (w = ::BIO_new(::BIO_s_mem())); }
    void set_rwbio(void) const { ::SSL_set_bio(ssl, r, w); }
    void set_connect_state(void) const { ::SSL_set_connect_state(ssl); }
    void set_accept_state(void) const { ::SSL_set_accept_state(ssl); }
    bool set_hostname(const char HOST[]) const {
      return ::SSL_set_tlsext_host_name(ssl, HOST) > -1; }
    bool set_fd(int sockfd) const { return ::SSL_set_fd(ssl, sockfd) > -1; }
    bool do_handshake(void) const { return ::SSL_do_handshake(ssl) > -1; }
    void certinfo(std::string &, std::string &, std::string &) const;
    bool connect(const char []) override;
    void readfilter(char p) override { ::BIO_write(r, &p, sizeof p); }
    bool postread(char &p) override { 
      return ::SSL_read(ssl, &p, sizeof p) > 0; }
    bool write(const std::string &) const override;
  };
 
  // Mandatory
  using Client_cb = std::function<void(const char)>;
  // Idempotent Client Callback Writer
  static Client_cb const IDCB { [](const char) { } };
  enum class Meth { GET, POST, PUT, DELETE };
  
  namespace Handle {
    struct Req {
      const Meth METH { Meth::GET };
      const std::vector<std::string> HEAD;
      const std::string DATA, ENDP { "/" };
    };
    
    class Xfr {
      std::variant<Req, std::string> vrr;
      Client_cb cb { IDCB };
    public:
      Xfr(void) = default;
      explicit Xfr(const Req &REQ) : vrr { REQ } { }
      Xfr(const Req &REQ, const Client_cb &CB) :
        vrr { REQ }, cb { CB } { }
      Req &req(void) { return std::get<Req>(vrr); }
      void setres(void) { vrr = std::string { }; }
      std::string &header(void) { return std::get<std::string>(vrr); }
      Client_cb &writercb(void) { return cb; };
    };
  }

  template<typename S>
  class Send {
    static std::string AGENT;
    static std::array<std::string, 4> METHSTR;
    std::string httpver;
  public:
    Send(void) = delete;
    explicit Send(const float);
    bool req(S &, const std::string &, const Handle::Req &) const;
  };

  template<typename S>
  std::string Send<S>::AGENT { "TCPRequest" };
  template<typename S>
  std::array<std::string, 4> Send<S>::METHSTR { "GET", "POST", "PUT", "DELETE" };
  
  template class Send<Http>;
  template class Send<Https>;

  struct Regex { 
    std::regex OK { std::regex("OK", std::regex_constants::icase) },
      CL { std::regex("Content-Length: ", std::regex_constants::icase) },
      TE { std::regex("Transfer-Encoding: ", std::regex_constants::icase) },
      CHKD { std::regex("Chunked", std::regex_constants::icase) },
      CHKDHDR { std::regex("(0x)?[0-9a-f]+\r\n$", std::regex_constants::icase) };
  };

  template<typename S>
  class Recv {
    const unsigned TOMS { SINGULAR_TOMS };
    static Regex RGX;
  public:
    Recv(void) = default;
    explicit Recv(const unsigned TOMS) : TOMS { TOMS } { }
    bool ischkd(const std::string &) const;
    bool reqhdr(S &, std::string &) const;
    std::size_t parsecl(const std::string &) const;
    bool reqbody(S &, const Client_cb &, std::size_t) const;
    bool reqbody(S &s, const Client_cb &CB) const {
      return reqchkd(s, CB); }
    bool reqchkd(S &, const Client_cb &) const;
    bool reqchkd_raw(S &, const Client_cb &) const;
  };

  template<typename S>
  Regex Recv<S>::RGX;

  template class Recv<Http>;
  template class Recv<Https>;
  
  template<typename S>
  class Client {
    const float VER { DEFAULT_HTTPVER };
    const std::string HOST;
    S sock;
  public:
    Client(void) = delete;
    Client(const float, const char [], const char []);
    bool performreq(Handle::Xfr &, const unsigned = SINGULAR_TOMS);
    void close(void) { sock.Http::deinit(); }
  };

  template class Client<Http>;
  template class Client<Https>;

  template<typename S>
  class MultiClient {
    static constexpr auto MAX_N { 32 };
    const float VER { DEFAULT_HTTPVER };
    const std::string HOST;
    std::array<S, MAX_N> SOCK;
    std::bitset<MAX_N> CONN;
  public:
    MultiClient(void) = delete;
    MultiClient(const float, const char [], const char [], const unsigned);
    bool performreq(std::vector<std::reference_wrapper<Handle::Xfr>> &, 
      const unsigned = SINGULAR_TOMS);
    decltype(MAX_N) count(void) const { return CONN.count(); }
  };

  template class MultiClient<Http>;
  template class MultiClient<Https>;

  template<typename S>
  using Server_cb = std::function<bool(S &)>;
  
  template<typename S>
  class Server {
    S sock;  // Master
    std::vector<std::unique_ptr<S>> SOCK;  // Slaves
    std::atomic<bool> quit { };
  public:
    Server(void) = delete;
    explicit Server(const char []);
    bool poll_listen(const int TOMS) { return sock.pollin(TOMS); }
    void recv_client(const char [], const char []);
    void run(const Server_cb<S> &, const char [] = CERT, const char [] = KEY);
    void exit(void) { quit = true; }
  };

  template class Server<Http>;
  template class Server<Https>;
}
