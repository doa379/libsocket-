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

#include <sys/socket.h>
#include <netdb.h>
#include <openssl/err.h>
#include <cmath>
#include <libsockpp/sock.h>

static const float DEFAULT_HTTPVER { 2.0 };
static const char CERTPEM[] { "/tmp/cert.pem" };
static const char KEYPEM[] { "/tmp/key.pem" };
static const std::array<std::string, 4> REQ { "GET", "POST", "PUT", "DELETE" };
static const unsigned char LISTEN_QLEN { 16 };
static const unsigned INTERNAL_TIMEOUTMS { 5000 };
::SSL_CTX *sockpp::InitHttps::client, *sockpp::InitHttps::server;

bool sockpp::Http::init_client(const char HOST[], const char PORT[])
{
  struct addrinfo hints { };
  ::memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = { };
  hints.ai_protocol = { };
  struct addrinfo *result;
  if (::getaddrinfo(HOST, PORT, &hints, &result))
    return false;

  for (struct addrinfo *rp { result }; rp; rp = rp->ai_next)
  {
    if ((sockfd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) > -1 &&
          ::connect(sockfd, rp->ai_addr, rp->ai_addrlen) > -1)
    {
      ::freeaddrinfo(result);
      return true;
    }
    
    deinit();
  }

  ::freeaddrinfo(result);
  return false;
}

bool sockpp::Http::init_server(const char PORT[])
{
  struct addrinfo hints { };
  ::memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  hints.ai_protocol = { };
  hints.ai_canonname = { };
  hints.ai_addr = { };
  hints.ai_next = { };
  struct addrinfo *result;
  if (::getaddrinfo(nullptr, PORT, &hints, &result))
    return false;

  for (struct addrinfo *rp { result }; rp; rp = rp->ai_next)
  {
    if ((sockfd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) > -1 &&
          ::bind(sockfd, rp->ai_addr, rp->ai_addrlen) > -1 &&
            ::listen(sockfd, LISTEN_QLEN) > -1)
    {
      ::freeaddrinfo(result);
      return true;
    }

    deinit();
  }

  ::freeaddrinfo(result);
  return false;
}

void sockpp::Http::init_poll(void)
{
  pollfd.fd = sockfd;
  pollfd.events = POLLIN;
}

bool sockpp::Http::poll(const int timeout_ms)
{
  return ::poll(&pollfd, 1, timeout_ms) > 0 && pollin();
  // Poll retval > 0 success, < 0 fail, == 0 timeout
}

bool sockpp::Http::pollin(void)
{
  return pollfd.revents & POLLIN;
}

bool sockpp::Http::pollerr(void)
{
  return pollfd.revents & (POLLERR | POLLHUP | POLLNVAL);
}

bool sockpp::Http::connect(const char [])
{
  //return ::connect(sockfd, (struct sockaddr *) &sa, sizeof sa) > -1;
  return true;
}

bool sockpp::Http::read(char &p)
{
  return ::read(sockfd, &p, sizeof p) > 0;
}

bool sockpp::Http::write(const std::string &data)
{
  return ::write(sockfd, data.c_str(), data.size()) > 0;
}

int sockpp::Http::accept(void)
{
  return ::accept(sockfd, nullptr, nullptr);
  // Return a sockfd
}
/*  
bool sockpp::Http::bind(void)
{
  return ::bind(sockfd, (struct sockaddr *) &sa, sizeof sa) > -1;
}

bool sockpp::Http::listen(void)
{
  return ::listen(sockfd, LISTEN_QLEN) > -1;
}
*/
sockpp::InitHttps::InitHttps(void)
{
  InitHttps::init();
}

void sockpp::InitHttps::init(void)
{
  ::OpenSSL_add_ssl_algorithms();
  ::SSL_load_error_strings();
  client = ::SSL_CTX_new(::TLS_client_method()); 
  server = ::SSL_CTX_new(::TLS_server_method());
}
/*
sockpp::Https::Https(const ::SSL_METHOD *meth) noexcept : 
  ctx { ::SSL_CTX_new(meth) }, ssl { ::SSL_new(ctx) }
{

}

sockpp::Https::Https(const int sockfd, const ::SSL_METHOD *meth) noexcept : 
  Http { sockfd },
  ctx { ::SSL_CTX_new(meth) }, ssl { ::SSL_new(ctx) }
{

}
*/
sockpp::Https::Https(void) noexcept : 
  ssl { ::SSL_new(client) }
{

}

sockpp::Https::Https(const int sockfd) noexcept : 
  Http { sockfd }, ssl { ::SSL_new(client) }
{

}

sockpp::Https::~Https(void)
{
  if (ssl)
  {
    ::SSL_shutdown(ssl);
    ::SSL_free(ssl);
  }

/*
  if (ctx)
    ::SSL_CTX_free(ctx);
    */
}

bool sockpp::Https::configure_context(const std::string &certpem, const std::string &keypem)
{
  /*
  SSL_CTX_set_ecdh_auto(ctx, 1);
  if (::SSL_CTX_use_certificate_file(ctx, certpem.c_str(), SSL_FILETYPE_PEM) < 1)
    return false;
  if (keypem.size() && ::SSL_CTX_use_PrivateKey_file(ctx, keypem.c_str(), SSL_FILETYPE_PEM) < 1)
    return false;
  else if (!keypem.size() && ::SSL_CTX_use_PrivateKey_file(ctx, certpem.c_str(), SSL_FILETYPE_PEM) < 1)
    return false;
    */
  return true;
}

bool sockpp::Https::set_hostname(const char host[])
{
  return ::SSL_set_tlsext_host_name(ssl, host) > 0;
}

bool sockpp::Https::set_fd(void)
{
  return ::SSL_set_fd(ssl, sockfd) > 0;
}

bool sockpp::Https::connect(const char host[])
{
  return /*Http::connect() &&
    set_hostname(host) && */set_fd() &&
      ::SSL_connect(ssl) > 0;
}

bool sockpp::Https::poll(const int timeout_ms)
{
  return sockpp::Http::poll(timeout_ms);
}

bool sockpp::Https::read(char &p)
{
  return ::SSL_read(ssl, &p, sizeof p) > 0 && 1;
    //::SSL_has_pending(ssl);
}

bool sockpp::Https::write(const std::string &data)
{
  return ::SSL_write(ssl, data.c_str(), data.size()) > 0;
}

bool sockpp::Https::clear(void)
{
  return ::SSL_clear(ssl) > 0;
}

bool sockpp::Https::accept(void)
{
  return ::SSL_accept(ssl) > 0;
}
/*
::SSL_CTX *sockpp::Https::ssl_ctx(::SSL_CTX *ctx)
{
  return ::SSL_set_SSL_CTX(ssl, ctx);
}
*/
int sockpp::Https::error(int err)
{
  return ::SSL_get_error(ssl, err);
}

void sockpp::Https::certinfo(std::string &cipherinfo, std::string &cert, std::string &issue)
{
  // Method must be called after connect()
  cipherinfo = std::string(::SSL_get_cipher(ssl));
  ::X509 *server_cert { ::SSL_get_peer_certificate(ssl) };
  if (!server_cert)
    return;

  char *certificate { ::X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0) };
  if (certificate)
  {
    cert = std::string(certificate);
    ::OPENSSL_free(certificate);
  }

  char *issuer { ::X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0) };
  if (issuer)
  {
    issue = std::string(issuer);
    ::OPENSSL_free(issuer);
  }

  ::X509_free(server_cert);
}

template<typename S>
bool sockpp::Recv<S>::is_chunked(const std::string &header)
{
  std::smatch match { };
  return std::regex_search(header, match, transfer_encoding_regex) &&
    std::regex_match(header.substr(match.prefix().length() + 19, 7), chunked_regex);
}
//////////////////////////////////////////////
/*
template<typename S>
bool sockpp::Recv<S>::req_header(std::string &header)
{
  char p { };
  while (!(header.rfind("\r\n\r\n") < std::string::npos) && sock.read(p))
    header += p;
  std::smatch match { };
  return std::regex_search(header, match, ok_regex);
}

template<typename S>
void sockpp::Recv<S>::req_body(std::string &body, const std::string &header)
{
  std::size_t l { };
  std::smatch match { };
  if (std::regex_search(header, match, content_length_regex) &&
      (l = std::stoull(header.substr(match.prefix().length() + 16,
        header.substr(match.prefix().length() + 16).find("\r\n")))))
    {
      char p { };
      while (body.size() < l && sock.read(p))
        body += p;
    }
}

template<typename S>
void sockpp::Recv<S>::req_body(const Cb &cb)
{
  std::string body;
  std::size_t l { };
  char p { };
  while (sock.read(p))
  {
    body += p;
    if (body == "\r\n");
    else if (!l && body.rfind("\r\n") < std::string::npos)
    {
      body.erase(body.end() - 2, body.end());
      if (!(l = std::stoull(body, nullptr, 16)))
        break;
    }
    else if (body.size() == l)
    {
      cb(body);
      l = 0;
    }
    else
      continue;

    body.clear();
  }
}

template<typename S>
void sockpp::Recv<S>::req_raw(const Cb &cb)
{
  std::string body;
  char p { };
  while (sock.read(p))
  {
    body += p;
    cb(body);
    body.clear();
  }
}
*/
//////////////////////////////////////////////////////

template<typename S>
bool sockpp::Recv<S>::req_header(std::string &header)
{
  char p { };
  while (!(header.rfind("\r\n\r\n") < std::string::npos) && 
    sock.poll(INTERNAL_TIMEOUTMS) &&
      sock.read(p))
        header += p;
  std::smatch match { };
  return std::regex_search(header, match, ok_regex);
}

template<typename S>
void sockpp::Recv<S>::req_body(std::string &body, const std::string &header)
{
  std::size_t l { };
  std::smatch match { };
  if (std::regex_search(header, match, content_length_regex) &&
      (l = std::stoull(header.substr(match.prefix().length() + 16,
        header.substr(match.prefix().length() + 16).find("\r\n")))))
    {
      char p { };
      while (body.size() < l && 
          sock.poll(INTERNAL_TIMEOUTMS) && 
            sock.read(p))
        body += p;
    }
}

template<typename S>
void sockpp::Recv<S>::req_body(const Cb &cb)
{
  std::string body;
  std::size_t l { };
  char p { };
  while (sock.poll(INTERNAL_TIMEOUTMS) && sock.read(p))
  {
    body += p;
    if (body == "\r\n");
    else if (!l && body.rfind("\r\n") < std::string::npos)
    {
      body.erase(body.end() - 2, body.end());
      if (!(l = std::stoull(body, nullptr, 16)))
        break;
    }
    else if (body.size() == l)
    {
      cb(body);
      l = 0;
    }
    else
      continue;

    body.clear();
  }
}

template<typename S>
void sockpp::Recv<S>::req_raw(const Cb &cb)
{
  std::string body;
  char p { };
  while (sock.poll(INTERNAL_TIMEOUTMS) && sock.read(p))
  {
    body += p;
    cb(body);
    body.clear();
  }
}

template class sockpp::Recv<sockpp::Http>;
template class sockpp::Recv<sockpp::Https>;

template<typename S>
sockpp::Client<S>::Client(const float httpver, const std::string &host, const std::string &port) : 
  host { host }
{
  ::snprintf(this->httpver, sizeof this->httpver - 1, "%.1f", httpver);
  if (sock.init_client(host.c_str(), port.c_str()) && sock.connect(host.c_str()))
    sock.init_poll();
  else
    throw "Failed to init client";
}

template<typename S>
bool sockpp::Client<S>::sendreq(const Req req, const std::vector<std::string> &HEAD, const std::string &data, const std::string &endp)
{
  if (&REQ[req] > &REQ[REQ.size() - 1]
    || (req == GET && data.size()))
    return false;

  std::string request { 
    REQ[req] + " " + endp + " " + "HTTP/" + std::string(httpver) + "\r\n" +
    "Host: " + host + "\r\n" +
    "User-Agent: " + std::string(AGENT) + "\r\n" +
    "Accept: */*" + "\r\n" };

  for (auto &h : HEAD)
    request += h + "\r\n";

  if (data.size())
    request += "Content-Length: " + std::to_string(data.size()) + "\r\n\r\n" + data;

  request += "\r\n";
  return sock.write(request);
}

template<typename S>
bool sockpp::Client<S>::performreq(XHandle &h)
{
  if (sendreq(h.req, h.HEAD, h.data, h.endp) &&
      sock.poll(INTERNAL_TIMEOUTMS))
  {
    Recv<S> recv { sock };
    std::string swap;
    if (recv.req_header(swap))
    {
      h.header = swap;
      if (recv.is_chunked(h.header))
        recv.req_body(h.cb);
      else
      {
        swap.clear();
        recv.req_body(swap, h.header);
        h.body = swap;
      }
      return true;
    }
  }
  return false;
}

template class sockpp::Client<sockpp::Http>;
template class sockpp::Client<sockpp::Https>;

template<typename S>
sockpp::Multi<S>::Multi(const std::vector<std::reference_wrapper<sockpp::Client<S>>> &C) : C { C }
{

}

template<typename S>
void sockpp::Multi<S>::performreq(const std::vector<std::reference_wrapper<XHandle>> &H)
{
  auto N { (unsigned) ceil((float) H.size() / C.size()) };
  std::list<std::future<void>> F;
  for (auto &c : C)
  {
    auto i { &c - &C[0] };
    auto f { std::async(std::launch::async, 
      [&, i](void) {
        for (auto h { H.begin() + i * N }; h <  H.begin() + (i + 1) * N && h < H.end(); h++)
          c.get().performreq(*h);
      })
    };
  
    F.emplace_back(std::move(f));
  }

  F.remove_if([](auto &f) { 
    return f.wait_for(std::chrono::milliseconds(1)) == std::future_status::ready; });
}

template class sockpp::Multi<sockpp::Http>;
template class sockpp::Multi<sockpp::Https>;

template<typename S>
sockpp::Server<S>::Server(const char port[])
{
  if (sock.init_server(port))
    sock.init_poll();
  else
    throw "Failed to init server";

  /*
  if (sock.init_sd())
  {
    sock.init_sa(host, port);
    sock.init_poll();
    if (!sock.bind() || !sock.listen())
      throw "Failed to bind";
  }

  else
    throw "Failed to init sd";
    */
}

template<>
void sockpp::Server<sockpp::Http>::recv_client(const std::function<void(Http &)> &cb, const std::string &, const std::string &)
{
  auto f { std::async(std::launch::async, 
    [&](void) {
      Http sock { this->sock.accept() };
      sock.init_poll();
      cb(sock);
    }) 
  };

  F.emplace_back(std::move(f));
}

template<>
void sockpp::Server<sockpp::Https>::recv_client(const std::function<void(Https &)> &cb, const std::string &certpem, const std::string &keypem)
{
  /*
  auto f { std::async(std::launch::async, 
    [&, certpem, keypem](void) { 
      Https client;
      if (!client.configure_context(certpem, keypem) ||
        !client.set_hostname(host))
        return;
      auto sockfd { sock.Http::accept() };
      Https sock { sockfd };
      sock.init_poll();
      sock.set_fd();
      sock.ssl_ctx(client.ssl_ctx());
      if (sock.accept())
        cb(sock);
    })
  };

  F.emplace_back(std::move(f));
  */
}

template<typename S>
void sockpp::Server<S>::refresh_clients(void)
{
  F.remove_if([](auto &f) { 
    return f.wait_for(std::chrono::milliseconds(1)) == std::future_status::ready; });
}

template class sockpp::Server<sockpp::Http>;
template class sockpp::Server<sockpp::Https>;
