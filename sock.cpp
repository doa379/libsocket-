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

#include <cstring>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/err.h>
#include "sock.h"

sockpp::Http::Http(const int sd)
{
  init(sd);
  memset(&sa, 0, sizeof sa);
}

sockpp::Http::~Http(void)
{
  deinit();
}

bool sockpp::Http::init(const int sd)
{
  if (sd)
    this->sd = sd;
  else if ((this->sd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    return false;
  return true;
}

void sockpp::Http::deinit(void)
{
  struct linger lo { 1, 0 };
  setsockopt(sd, SOL_SOCKET, SO_LINGER, &lo, sizeof lo);
  close(sd);
}

bool sockpp::Http::init_connect(const std::string &hostname, const unsigned port)
{
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);
  struct hostent *host { gethostbyname(hostname.c_str()) };
  if (host)
  {
    sa.sin_addr.s_addr = *(long *) host->h_addr;
    return true;
  }
  
  return false;
}

bool sockpp::Http::connect(const std::string &)
{
  if (::connect(sd, (struct sockaddr *) &sa, sizeof sa) > -1)
    return true;
  return false;
}

bool sockpp::Http::read(char &p)
{
  if (::read(sd, &p, sizeof p) > -1)
    return true;
  return false;
}

bool sockpp::Http::write(const std::string &data)
{
  if (::write(sd, data.c_str(), data.size()) > -1)
  {
    fsync(sd);
    return true;
  }
  return false;
}

int sockpp::Http::accept(void)
{
  struct sockaddr_in addr;
  uint len { sizeof addr };
  return ::accept(sd, (struct sockaddr *) &addr, &len);
  // Return a sd
}
  
bool sockpp::Http::bind(void)
{
  if (::bind(sd, (struct sockaddr *) &sa, sizeof sa) > -1)
    return true;
  return false;
}

bool sockpp::Http::listen(void)
{
  if (::listen(sd, 1) > -1)
    return true;
  return false;
}

sockpp::InitHttps::InitHttps(void)
{
  InitHttps::init();
}

void sockpp::InitHttps::init(void)
{
  OpenSSL_add_ssl_algorithms();
  SSL_load_error_strings();
}

sockpp::Https::Https(const int sd, const SSL_METHOD *meth) noexcept : 
  Http(sd),
  ctx(SSL_CTX_new(meth)), ssl(SSL_new(ctx))
{

}

sockpp::Https::~Https(void)
{
  if (ssl)
  {
    SSL_shutdown(ssl);
    SSL_free(ssl);
  }

  if (ctx)
    SSL_CTX_free(ctx);
}

bool sockpp::Https::configure_context(const std::string &certpem, const std::string &keypem)
{
  SSL_CTX_set_ecdh_auto(ctx, 1);
  if (SSL_CTX_use_certificate_file(ctx, certpem.c_str(), SSL_FILETYPE_PEM) < 1)
    return false;
  if (keypem.size() && SSL_CTX_use_PrivateKey_file(ctx, keypem.c_str(), SSL_FILETYPE_PEM) < 1)
    return false;
  else if (!keypem.size() && SSL_CTX_use_PrivateKey_file(ctx, certpem.c_str(), SSL_FILETYPE_PEM) < 1)
    return false;
  return true;
}

bool sockpp::Https::set_hostname(const std::string &hostname)
{
  if (SSL_set_tlsext_host_name(ssl, hostname.c_str()) > 0)
    return true;
  return false;
}

bool sockpp::Https::set_fd(void)
{
  if (SSL_set_fd(ssl, sd) > 0)
    return true;
  return false;
}

bool sockpp::Https::connect(const std::string &hostname)
{
  if (Http::connect())
  {
    set_hostname(hostname);
    set_fd();
    if (SSL_connect(ssl) > 0)
      return true;
  }

  return false;
}

bool sockpp::Https::read(char &p)
{
  if (SSL_read(ssl, &p, sizeof p) > 0)
    return true;
  return false;
}

bool sockpp::Https::write(const std::string &data)
{
  if (SSL_write(ssl, data.c_str(), data.size()) > 0)
    return true;
  return false;
}

bool sockpp::Https::clear(void)
{
  if (SSL_clear(ssl) > 0)
    return true;

  return false;
}

bool sockpp::Https::accept(void)
{
  if (SSL_accept(ssl) > 0)
    return true;
  return false;
}

SSL_CTX *sockpp::Https::ssl_ctx(SSL_CTX *ctx)
{
  return SSL_set_SSL_CTX(ssl, ctx);
}

int sockpp::Https::error(int err)
{
  return SSL_get_error(ssl, err);
}

void sockpp::Https::certinfo(std::string &cipherinfo, std::string &cert, std::string &issue)
{
  // Method must be called after connect()
  cipherinfo = std::string(SSL_get_cipher(ssl));
  X509 *server_cert { SSL_get_peer_certificate(ssl) };
  if (!server_cert)
    return;

  char *certificate { X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0) };
  if (certificate)
  {
    cert = std::string(certificate);
    OPENSSL_free(certificate);
  }

  char *issuer { X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0) };
  if (issuer)
  {
    issue = std::string(issuer);
    OPENSSL_free(issuer);
  }

  X509_free(server_cert);
}

template<typename S>
bool sockpp::Recv::req_header(std::string &header, S &sock)
{
  while (!(header.rfind("\r\n\r\n") < std::string::npos) && sock.read(p))
    header += p;
  
  if (!std::regex_search(header, match, ok_regex))
    return false;

  return true;
}

template bool sockpp::Recv::req_header(std::string &, Http &);
template bool sockpp::Recv::req_header(std::string &, HttpsCli &);
template bool sockpp::Recv::req_header(std::string &, HttpsSvr &);

bool sockpp::Recv::is_chunked(const std::string &header)
{
  if (std::regex_search(header, match, transfer_encoding_regex) &&
    std::regex_match(header.substr(match.prefix().length() + 19, 7), chunked_regex))
    return true;
  return false;
}

template<typename S>
void sockpp::Recv::req_body(std::string &body, const std::string &header, S &sock)
{
  std::size_t l { };
  if (std::regex_search(header, match, content_length_regex) &&
      (l = std::stoull(header.substr(match.prefix().length() + 16,
        header.substr(match.prefix().length() + 16).find("\r\n")))))
    while (body.size() < l && sock.read(p))
      body += p;
}

template void sockpp::Recv::req_body(std::string &, const std::string &, Http &sock);
template void sockpp::Recv::req_body(std::string &, const std::string &, HttpsCli &sock);
template void sockpp::Recv::req_body(std::string &, const std::string &, HttpsSvr &sock);

template<typename T, typename S>
void sockpp::Recv::req_body(const unsigned timeout, const Cb &cb, S &sock)
{
  std::string body;
  std::size_t l { };
  auto now { time.now() };
  while (sock.read(p) && time.diffpt<T>(time.now(), now) < timeout)
  {
    body += p;
    now = time.now();
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

template<typename T, typename S>
void sockpp::Recv::req_raw(const unsigned timeout, const Cb &cb, S &sock)
{
  std::string body;
  auto now { time.now() };
  while (sock.read(p) && time.diffpt<T>(time.now(), now) < timeout)
  {
    body += p;
    cb(body);
    now = time.now();
    body.clear();
  }
}

template<typename S>
sockpp::Client<S>::Client(const float httpver, const std::string &hostname, const unsigned port) : 
  hostname(hostname), port(port)
{
  snprintf(this->httpver, sizeof this->httpver - 1, "%.1f", httpver);
}

template<typename S>
bool sockpp::Client<S>::connect(void)
{
  if (sock.init_connect(hostname, port))
    return sock.connect(hostname);
  return false;
}

template<typename S>
bool sockpp::Client<S>::sendreq(const Req req, const std::vector<std::string> &HEAD, const std::string &data, const std::string &endp)
{
  if (&REQ[req] > &REQ[REQ.size() - 1]
    || (req == GET && data.size()))
    return false;

  std::string request { 
    REQ[req] + " " + endp + " " + "HTTP/" + std::string(httpver) + "\r\n" +
    "Host: " + hostname + "\r\n" +
    "User-Agent: " + std::string(agent) + "\r\n" +
    "Accept: */*" + "\r\n" };

  for (auto &h : HEAD)
    request += h + "\r\n";

  if (data.size())
    request += "Content-Length: " + std::to_string(data.size()) + "\r\n\r\n" + data;

  request += "\r\n";
  return sock.write(request);
}

template<typename S>
template<typename T>
bool sockpp::Client<S>::performreq(const unsigned timeout, XHandle &h)
{
  if (sendreq(h.req, h.HEAD, h.data, h.endp))
  {
    Recv recv;
    std::string swap;
    if (recv.req_header(swap, sock))
    {
      h.header = swap;
      if (recv.is_chunked(h.header))
        recv.req_body<T>(timeout, h.cb, sock);
      else
      {
        swap.clear();
        recv.req_body(swap, h.header, sock);
        h.body = swap;
      }
      return true;
    }
  }
  return false;
}

template class sockpp::Client<sockpp::Http>;
template class sockpp::Client<sockpp::HttpsCli>;
template bool sockpp::Client<sockpp::Http>::performreq<std::chrono::seconds>(const unsigned, XHandle &);
template bool sockpp::Client<sockpp::HttpsCli>::performreq<std::chrono::seconds>(const unsigned, XHandle &);
template bool sockpp::Client<sockpp::Http>::performreq<std::chrono::milliseconds>(const unsigned, XHandle &);
template bool sockpp::Client<sockpp::HttpsCli>::performreq<std::chrono::milliseconds>(const unsigned, XHandle &);

template<typename S>
sockpp::Multi<S>::Multi(const std::vector<std::reference_wrapper<sockpp::Client<S>>> &C) : C(C)
{

}

template<typename S>
unsigned sockpp::Multi<S>::connect(void)
{
  unsigned n { };
  for (auto &c : C)
    if (c.get().connect())
      n++;

  return n;
}
// TODO: This method needs improvement
template<typename S>
template<typename T>
void sockpp::Multi<S>::performreq(const unsigned timeout, const std::vector<std::reference_wrapper<XHandle>> &H)
{
  std::size_t N { H.size() / C.size() }, R { H.size() % C.size() };
  std::vector<std::vector<std::reference_wrapper<XHandle>>> JJ;
  for (auto h { H.begin() }; h < H.end(); h += N)
  {
    std::vector<std::reference_wrapper<XHandle>> J;
    for (auto j { h }; j < h + N && j < H.end(); j++)
      J.emplace_back(*j);
    JJ.emplace_back(std::move(J));
  }
  // Less optimum case
  if (R)
  {
    std::vector<std::reference_wrapper<XHandle>> J;
    for (auto j { H.end() - R }; j < H.end(); j++)
      J.emplace_back(*j);
    JJ.emplace_back(std::move(J));
  }
  // Run asyncs
  std::list<std::future<void>> C;
  for (auto &J : JJ)
  {
    auto i { (&J - &JJ[0]) % this->C.size() };
    auto c { std::async(std::launch::async, 
      [&, i](void) {
        for (auto &j : J)
          this->C[i].get().template performreq<T>(timeout, j.get());
        }
      )
    };
    
    C.emplace_back(std::move(c));
  }
  
  C.remove_if([](auto &c) { 
    return c.wait_for(std::chrono::milliseconds(1)) == std::future_status::ready; });
/*
  struct pollfd PFD[MAX_CLIENTS] { };
  for (auto i { 0U }; i < C.size(); i++)
  {
    PFD[i].fd = C[i].get().sock->get();
    PFD[i].events = POLLIN;
  }

  const auto init { time.now() };
  std::bitset<MAX_CLIENTS> M;
  while (M.count() < C.size() && time.diffpt<T>(time.now(), init) < timeout)
  {
    poll(PFD, C.size(), 100);
    for (auto i { 0U }; i < C.size(); i++)
      if (PFD[i].revents & POLLIN && !M[i])
      {
        if (CB.size())
          C[i].get().recvreq(CB[i]);
        else
          C[i].get().recvreq();
        M |= 1 << i;
      }
  }
*/
}

template<typename S>
template<typename T>
void sockpp::Multi<S>::performreq(const unsigned timeout, const std::size_t async, const std::vector<std::reference_wrapper<XHandle>> &H)
{
  const auto nasync { std::min(async, H.size()) };
  std::list<std::future<void>> C;
  for (auto h { H.begin() }; h < H.end(); h += nasync)
  {
    for (auto j { h }; j < h + nasync && j < H.end(); j++)
    { 
      auto c { std::async(std::launch::async, 
        [&, j](void) { 
          auto init { time.now() };
          auto i { j - H.begin() };
          Client<S> &c { this->C[i].get() };
          // Implicitly verify state of client sd
          if (c.sendreq(j->get().req, j->get().HEAD, j->get().data, j->get().endp))
            while (time.diffpt<T>(time.now(), init) < timeout && 
                !c.template performreq<T>(timeout, *j))
              std::this_thread::sleep_for(std::chrono::milliseconds(1));
          }
        )
      };

      C.emplace_back(std::move(c));
    }

    C.remove_if([](auto &c) { 
      return c.wait_for(std::chrono::milliseconds(1)) == std::future_status::ready; });
  }
}

template class sockpp::Multi<sockpp::Http>;
template class sockpp::Multi<sockpp::HttpsCli>;
template void sockpp::Multi<sockpp::Http>::performreq<std::chrono::seconds>(const unsigned, const std::vector<std::reference_wrapper<XHandle>> &);
template void sockpp::Multi<sockpp::HttpsCli>::performreq<std::chrono::seconds>(const unsigned, const std::vector<std::reference_wrapper<XHandle>> &);
template void sockpp::Multi<sockpp::Http>::performreq<std::chrono::milliseconds>(const unsigned, const std::vector<std::reference_wrapper<XHandle>> &);
template void sockpp::Multi<sockpp::HttpsCli>::performreq<std::chrono::milliseconds>(const unsigned, const std::vector<std::reference_wrapper<XHandle>> &);
template void sockpp::Multi<sockpp::Http>::performreq<std::chrono::seconds>(const unsigned, const std::size_t, const std::vector<std::reference_wrapper<XHandle>> &);
template void sockpp::Multi<sockpp::HttpsCli>::performreq<std::chrono::seconds>(const unsigned, const std::size_t, const std::vector<std::reference_wrapper<XHandle>> &);
template void sockpp::Multi<sockpp::Http>::performreq<std::chrono::milliseconds>(const unsigned, const std::size_t, const std::vector<std::reference_wrapper<XHandle>> &);
template void sockpp::Multi<sockpp::HttpsCli>::performreq<std::chrono::milliseconds>(const unsigned, const std::size_t, const std::vector<std::reference_wrapper<XHandle>> &);

template<typename S>
sockpp::Server<S>::Server(const std::string &hostname, const unsigned port) :
  hostname(hostname), port(port)
{

}

template<typename S>
bool sockpp::Server<S>::connect(void)
{
  if (sock.init_connect(hostname, port) &&
    sock.bind() &&
      sock.listen())
  {
    listensd.fd = sock.get();
    listensd.events = POLLIN;
    return true;
  }

  return false;
}

template<typename S>
bool sockpp::Server<S>::poll_listen(unsigned timeout_ms)
{
  poll(&listensd, 1, timeout_ms);
  if (listensd.revents & POLLIN)
    return true;
  return false;
}

template<>
std::shared_ptr<sockpp::Http> sockpp::Server<sockpp::Http>::recv_client(const std::string &, const std::string &)
{
  return std::make_shared<Http>(sock.accept());
}

template<>
std::shared_ptr<sockpp::HttpsSvr> sockpp::Server<sockpp::HttpsSvr>::recv_client(const std::string &certpem, const std::string &keypem)
{
  auto client { std::make_shared<HttpsCli>() };
  if (!client->configure_context(certpem, keypem) ||
    !client->set_hostname(hostname))
    return nullptr;
  auto sd { sock.Http::accept() };
  auto socks { std::make_shared<HttpsSvr>(sd) };
  socks->set_fd();
  socks->ssl_ctx(client->ssl_ctx());
  if (socks->accept())
    return socks;
  return nullptr;
}

template<typename S>
void sockpp::Server<S>::new_client(std::shared_ptr<S> s, const std::function<void(S &)> &cb)
{
  auto c { std::async(std::launch::async, [=](void) { cb(*s); }) };
  C.emplace_back(std::move(c));
}

template<typename S>
void sockpp::Server<S>::refresh_clients(void)
{
  C.remove_if([](auto &c) { 
    return c.wait_for(std::chrono::milliseconds(1)) == std::future_status::ready; });
}

template class sockpp::Server<sockpp::Http>;
template class sockpp::Server<sockpp::HttpsSvr>;
