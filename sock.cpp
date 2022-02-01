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

#include <netdb.h>
#include <cmath>
#include <libsockpp/sock.h>
#include <libsockpp/time.h>

static const std::array<std::string, 4> REQ { "GET", "POST", "PUT", "DELETE" };
static const unsigned char LISTEN_QLEN { 16 };

bool sockpp::Http::init_client(const char HOST[], const char PORT[]) {
  struct ::addrinfo hints { };
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = { };
  hints.ai_protocol = { };
  struct ::addrinfo *result;
  if (::getaddrinfo(HOST, PORT, &hints, &result))
    return false;

  for (struct ::addrinfo *rp { result }; rp; rp = rp->ai_next) {
    if ((sockfd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) > -1 &&
          ::connect(sockfd, rp->ai_addr, rp->ai_addrlen) > -1) {
      ::freeaddrinfo(result);
      return true;
    }
    
    deinit();
  }

  ::freeaddrinfo(result);
  return false;
}

bool sockpp::Http::init_server(const char PORT[]) {
  struct ::addrinfo hints { };
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  hints.ai_protocol = { };
  hints.ai_canonname = { };
  hints.ai_addr = { };
  hints.ai_next = { };
  struct ::addrinfo *result;
  if (::getaddrinfo(nullptr, PORT, &hints, &result))
    return false;

  for (struct ::addrinfo *rp { result }; rp; rp = rp->ai_next) {
    if ((sockfd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) > -1 &&
          ::bind(sockfd, rp->ai_addr, rp->ai_addrlen) > -1 &&
            ::listen(sockfd, LISTEN_QLEN) > -1) {
      ::freeaddrinfo(result);
      return true;
    }

    deinit();
  }

  ::freeaddrinfo(result);
  return false;
}

void sockpp::Http::deinit(void)  {
  if (sockfd > -1 && ::close(sockfd) > -1)
    sockfd = -1;
}

void sockpp::Http::init_poll(void) {
  pollfd.fd = sockfd;
}

bool sockpp::Http::pollin(const int timeout_ms) {
  pollfd.events = POLLIN;
  pollfd.revents = 0;
  return ::poll(&pollfd, 1, timeout_ms) > 0 && (pollfd.revents & POLLIN);
  // Poll retval > 0 success, < 0 fail, == 0 timeout
}

bool sockpp::Http::pollout(const int timeout_ms) {
  pollfd.events = POLLOUT;
  pollfd.revents = 0;
  return ::poll(&pollfd, 1, timeout_ms) > 0 && (pollfd.revents & POLLOUT);
}

bool sockpp::Http::pollerr(const int timeout_ms) {
  auto event { POLLERR | POLLHUP | POLLNVAL };
  pollfd.events = event;
  pollfd.revents = 0;
  return ::poll(&pollfd, 1, timeout_ms) > 0 && (pollfd.revents & event);
}

bool sockpp::Http::read(char &p) const {
  return ::read(sockfd, &p, sizeof p) > 0;
}

bool sockpp::Http::write(const std::string &req) const {
  return ::write(sockfd, req.c_str(), req.size()) > 0;
}

void sockpp::Https::deinit(void) const {
  if (ssl) {
    ::SSL_shutdown(ssl);
    ::SSL_free(ssl);
  }

  if (ctx)
    ::SSL_CTX_free(ctx);
}

bool sockpp::Https::configure_ctx(const char CERT[], const char KEY[]) const {
  SSL_CTX_set_ecdh_auto(ctx, 1);
  return SSL_CTX_use_certificate_file(ctx, CERT, SSL_FILETYPE_PEM) > 0 &&
      SSL_CTX_use_PrivateKey_file(ctx, KEY, SSL_FILETYPE_PEM) > 0 &&
        SSL_CTX_check_private_key(ctx) > 0;
}

void sockpp::Https::connect(const char HOST[]) {
  Https::init_client();
  init();
  set_hostname(HOST);
  set_connect_state();
  set_fd(Http::sockfd);
  do_handshake();
  init_rbio();
  init_wbio();
  set_rwbio();
}

void sockpp::Https::readfilter(char p) {
  ::BIO_write(r, &p, sizeof p);
}

bool sockpp::Https::postread(char &p) {
  return ::SSL_read(ssl, &p, sizeof p) > 0;
}

bool sockpp::Https::write(const std::string &req) const {
  char buffer[16384] { };
  ssize_t Nenc { };
  return ::SSL_write(ssl, req.c_str(), req.size()) > 0 &&
    (Nenc = ::BIO_read(w, buffer, sizeof buffer)) > 0 &&
      ::write(sockfd, buffer, Nenc) > 0;
}

void sockpp::Https::certinfo(std::string &cipherinfo, std::string &cert, std::string &iss) const {
  cipherinfo = std::string { ::SSL_get_cipher(ssl) };
  ::X509 *server_cert { ::SSL_get_peer_certificate(ssl) };
  if (!server_cert)
    return;

  auto CERT { ::X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0) };
  if (CERT) {
    cert = std::string { CERT };
    ::OPENSSL_free(CERT);
  }

  auto ISS { ::X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0) };
  if (ISS) {
    iss = std::string { ISS };
    ::OPENSSL_free(ISS);
  }

  ::X509_free(server_cert);
}

template<typename S>
bool sockpp::Send::req(S &s, const float ver, const std::string &host, const Req req, const std::vector<std::string> &HEAD, const std::string &data, const std::string &endp) const {
  if (&REQ[static_cast<int>(req)] > &REQ[REQ.size() - 1] || (req == Req::GET && data.size()))
    return false;
  
  char httpver[8] { };
  ::snprintf(httpver, sizeof httpver - 1, "%.1f", ver);
  std::string request { 
    REQ[static_cast<int>(req)] + " " + endp + " " + "HTTP/" + std::string { httpver } + "\r\n" +
      "Host: " + host + "\r\n" +
        "User-Agent: " + std::string { AGENT } + "\r\n" +
          "Accept: */*" + "\r\n" 
    };

  for (auto &h : HEAD)
    request += h + "\r\n";

  if (data.size())
    request += "Content-Length: " + std::to_string(data.size()) + "\r\n\r\n" + data;

  request += "\r\n";
  return s.write(request);
}

bool sockpp::Recv::is_chunked(const std::string &header) const {
  std::smatch match { };
  return std::regex_search(header, match, transfer_encoding_regex) &&
    std::regex_match(header.substr(match.prefix().length() + 19, 7), chunked_regex);
}

template<typename S>
bool sockpp::Recv::req_header(S &s, std::string &header) const {
  char p { };
  while (s.pollin(timeout_ms) && s.read(p)) {
    s.readfilter(p);
    while (s.postread(p)) {
      header += p;
      if ((ssize_t) header.rfind("\r\n\r\n") > -1)
        return true;
    }
  }

  return false;
}

std::size_t sockpp::Recv::parse_cl(const std::string &header) const {
  std::size_t cl { };
  std::smatch match { };
  if (std::regex_search(header, match, content_length_regex) &&
      (cl = std::stoull(header.substr(match.prefix().length() + 16,
        header.substr(match.prefix().length() + 16).find("\r\n")))));
  return cl;
}

template<typename S>
bool sockpp::Recv::req_body(S &s, std::string &body, const std::size_t cl) const {
  char p { };
  while (body.size() < cl && s.postread(p))
    body += p;
  if (body.size() == cl)
    return true;

  while (s.pollin(timeout_ms) && s.read(p)) {
    s.readfilter(p);
    while (s.postread(p)) {
      body += p;
      if (body.size() == cl)
        return true;
    }
  }

  return false;
}

template<typename S>
bool sockpp::Recv::req_chunked(S &s, const Cb &cb, std::string &body) const {
  char p { };
  std::size_t l { };
  while (s.pollin(timeout_ms) && s.read(p)) {
    s.readfilter(p);
    while (s.postread(p)) {
      body += p;
      if (body == "\r\n");
      else if (l == 0 && (ssize_t) body.rfind("\r\n") > -1) {
        body.erase(body.end() - 2, body.end());
        try {
          l = std::stoull(body, nullptr, 16);
        } catch (...) { return false; }

        if (l == 0)
          return true;
      } else if (body.size() == l) {
        cb(body);
        l = 0;
      } else
          continue;
      
      body.clear();
    }
  }

  return true;
}

template<typename S>
bool sockpp::Recv::req_chunked_raw(S &s, const Cb &cb, std::string &body) const {
  char p { };
  while (s.pollin(timeout_ms) && s.read(p)) {
    s.readfilter(p);
    while (s.postread(p)) {
      body += p;
      cb(body);
      body.clear();
    }
  }

  return true;
}

template<typename S>
sockpp::Client<S>::Client(const float ver, const char HOST[], const char PORT[]) : 
  ver { ver }, host { std::string { HOST } } {
  if (sock.Http::init_client(HOST, PORT)) {
    sock.connect(HOST);
    sock.init_poll();
  } else
      throw "Failed to init client";
}

template<typename S>
bool sockpp::Client<S>::performreq(XHandle &h, const unsigned timeout_ms) {
  Send send;
  Recv recv { timeout_ms };
  if (send.req(sock, ver, host, h.req, h.HEAD, h.data, h.endp) && recv.req_header(sock, h.header)) {
    if (recv.is_chunked(h.header))
      return recv.req_body(sock, h.cb, h.body);
    else {
      auto cl { recv.parse_cl(h.header) };
      return cl && recv.req_body(sock, h.body, cl);
    }
  }

  return false;
}

template class sockpp::Client<sockpp::Http>;
template class sockpp::Client<sockpp::Https>;

template<typename S>
sockpp::MultiClient<S>::MultiClient(const float ver, const char HOST[], const char PORT[], const unsigned N) : 
  ver { ver }, host { std::string { HOST } } {
  for (auto i { 0U }; i < N && N < MAX_N; i++) {
    S &sock { SOCK[i] };
    if (sock.Http::init_client(HOST, PORT)) {
      sock.connect(HOST);
      sock.init_poll();
      count++;
    }
  }
  
  if (!count)
    throw "Failed to init client";
}

template<typename S>
bool sockpp::MultiClient<S>::performreq(const std::vector<std::reference_wrapper<XHandle>> &H, const unsigned timeout_ms) {
  Send send;
  for (auto i { 0U }; i < count; i++)
    if (!send.req(SOCK[i], ver, host, H[i].get().req, H[i].get().HEAD, H[i].get().data, H[i].get().endp))
      return false;

  struct X {
    bool head { }, ischunked { }, body { };
    std::size_t cl { };
  };

  std::vector<X> XH(count);
  Recv recv { sockpp::MULTI_TIMEOUTMS };
  unsigned complete { };
  sockpp::Time time;
  auto init_time { time.now() };
  while (complete < count && time.diffpt<std::chrono::milliseconds>(time.now(), init_time) < timeout_ms)
    for (auto i { 0U }; i < count; i++)
      if (!XH[i].head && recv.req_header(SOCK[i], H[i].get().header)) {
        complete++;
        XH[i].head = 1;
        if (recv.is_chunked(H[i].get().header))
          XH[i].ischunked = 1;
        else
          XH[i].cl = recv.parse_cl(H[i].get().header);
      }

  complete = 0;
  while (complete < count && time.diffpt<std::chrono::milliseconds>(time.now(), init_time) < timeout_ms)
    for (auto i { 0U }; i < count; i++)
      if ((XH[i].ischunked && !XH[i].body && recv.req_body(SOCK[i], H[i].get().cb, H[i].get().body)) ||
            (XH[i].cl && !XH[i].body && recv.req_body(SOCK[i], H[i].get().body, XH[i].cl))) {
              XH[i].body = 1;
              complete++;
      }

  return true;
}

template class sockpp::MultiClient<sockpp::Http>;
template class sockpp::MultiClient<sockpp::Https>;

template<typename S>
sockpp::Server<S>::Server(const char PORT[]) { // Construct a server for each client
  if (sock.Http::init_server(PORT))
    sock.init_poll();
  else
    throw "Failed to init server";
}

template<>
void sockpp::Server<sockpp::Http>::recv_client(const std::function<void(Http &)> &cb, const char [], const char []) {
  Http server { this->sock.accept() };
  server.init_poll();
  cb(server);
}

template<>
void sockpp::Server<sockpp::Https>::recv_client(const std::function<void(Https &)> &cb, const char CERT[], const char KEY[]) {
  Https client;
  client.init_client();
  if (!client.configure_ctx(CERT, KEY))
    return;
  auto sockfd { sock.Http::accept() };
  Https server { sockfd };
  server.init_server();
  server.init();
  server.set_ctx(client.get_ctx());
  server.set_accept_state();
  server.set_fd(sockfd);
  server.do_handshake();
  server.init_rbio();
  server.init_wbio();
  server.set_rwbio();
  server.init_poll();
  cb(server);
}
// TODO: Handle multiple clients
template class sockpp::Server<sockpp::Http>;
template class sockpp::Server<sockpp::Https>;
