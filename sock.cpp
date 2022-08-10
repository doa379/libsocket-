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

#include <netdb.h>
#include <cmath>
#include <libsockpp/sock.h>
#include <libsockpp/time.h>

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

void sockpp::Http::deinit(void) {
  if (sockfd > -1 && ::close(sockfd) > -1)
    sockfd = -1;
}

bool sockpp::Http::pollin(const int TOMS) {
  pollfd.events = POLLIN;
  pollfd.revents = 0;
  return ::poll(&pollfd, 1, TOMS) > 0 && (pollfd.revents & POLLIN);
  // Poll retval > 0 success, < 0 fail, == 0 timeout
}

bool sockpp::Http::pollout(const int TOMS) {
  pollfd.events = POLLOUT;
  pollfd.revents = 0;
  return ::poll(&pollfd, 1, TOMS) > 0 && (pollfd.revents & POLLOUT);
}

bool sockpp::Http::pollerr(const int TOMS) {
  auto event { POLLERR | POLLHUP | POLLNVAL };
  pollfd.events = event;
  pollfd.revents = 0;
  return ::poll(&pollfd, 1, TOMS) > 0 && (pollfd.revents & event);
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

bool sockpp::Https::connect(const char HOST[]) {
  if (Https::init_client() && init() && set_hostname(HOST)) {
      set_connect_state();
      if (set_fd(Http::sockfd) && do_handshake() && init_rbio() && init_wbio()) {
        set_rwbio();
        return true;
      }
  }

  return false;
}

bool sockpp::Https::write(const std::string &req) const {
  char buffer[sockpp::SBN] { };
  ssize_t Nenc { };
  return ::SSL_write(ssl, req.c_str(), req.size()) > 0 &&
    (Nenc = ::BIO_read(w, buffer, sizeof buffer)) > 0 &&
      ::write(sockfd, buffer, Nenc) > 0;
}

void sockpp::Https::certinfo(std::string &cipherinfo, std::string &cert, std::string &iss) const {
  cipherinfo = std::string { ::SSL_get_cipher(ssl) };
  ::X509 *server_cert { ::SSL_get_peer_certificate(ssl) };
  if (!server_cert) return;

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
bool sockpp::Send<S>::req(S &s, const std::string &HOST, const Handle::Req &req) const {
  if (&METHSTR[static_cast<int>(req.METH)] > &METHSTR[METHSTR.size() - 1] ||
      (req.METH == Meth::GET && req.DATA.size()))
    return false;
  
  std::string request { 
    METHSTR[static_cast<int>(req.METH)] + " " + req.ENDP + " " +
      "HTTP/1.1" + "\r\n" +
        "Host: " + HOST + "\r\n" +
          "User-Agent: " + AGENT + "\r\n" +
            "Accept: */*" + "\r\n" 
    };

  for (const auto &h : req.HEAD)
    request += h + "\r\n";

  if (req.DATA.size())
    request += "Content-Length: " + std::to_string(req.DATA.size()) +
      "\r\n\r\n" + req.DATA;

  request += "\r\n";
  return s.write(request);
}

template<typename S>
bool sockpp::Recv<S>::ischkd(const std::string &HDR) const {
  std::smatch match { };
  return std::regex_search(HDR, match, RGX.TE) &&
    std::regex_match(HDR.substr(match.prefix().length() + 19, 7), RGX.CHKD);
}

template<typename S>
bool sockpp::Recv<S>::reqhdr(S &s, std::string &hdr) const {
  char p { };
  while (s.pollin(TOMS) && s.read(p)) {
    s.readfilter(p);
    while (s.postread(p)) {
      hdr += p;
      if (static_cast<ssize_t>(hdr.rfind("\r\n\r\n")) > -1)
        return true;
    }
  }

  return false;
}

template<typename S>
std::size_t sockpp::Recv<S>::parsecl(const std::string &HDR) const {
  std::size_t l { };
  std::smatch match { };
  if (std::regex_search(HDR, match, RGX.CL) &&
      (l = std::stoull(HDR.substr(match.prefix().length() + 16,
        HDR.substr(match.prefix().length() + 16).find("\r\n")))));

  return l;
}

template<typename S>
bool sockpp::Recv<S>::reqbody(S &s, const Client_cb &CB, std::size_t l) const {
  char p { };
  while (l && s.postread(p)) {
    CB(p);
    l--;
  }

  if (!l)
    return true;

  while (l && s.pollin(TOMS) && s.read(p)) {
    s.readfilter(p);
    while (l && s.postread(p)) {
      CB(p);
      l--;
    }
  }

  return !l;
}

template<typename S>
bool sockpp::Recv<S>::reqchkd(S &s, const Client_cb &CB) const {
  char p { };
  std::string len;
  std::smatch match { };
  while (s.pollin(TOMS) && s.read(p)) {
    s.readfilter(p);
    while (s.postread(p)) {
      len += p;
      if (std::regex_search(len, match, RGX.CHKDHDR)) {
        try {
          if (const auto L { std::stoull(len, nullptr, 16) }; L) {
            reqbody(s, CB, L);
            len.clear();
          } else
              return true;
        } catch (...) {
          return false;
        }
      }
    }
  }

  return false;
}

template<typename S>
void sockpp::Recv<S>::reqchkd_raw(S &s, const Client_cb &CB) const {
  char p { };
  while (s.pollin(TOMS) && s.read(p)) {
    s.readfilter(p);
    while (s.postread(p))
      CB(p);
  }
}

template<typename S>
sockpp::Client<S>::Client(const char HOST[], const char PORT[]) : 
  HOST { std::string { HOST } } {
  if (sock.Http::init_client(HOST, PORT) && sock.connect(HOST))
    sock.init_poll();
  else
    throw std::runtime_error("Unable to connect");
}

template<typename S>
bool sockpp::Client<S>::performreq(Handle::Xfr &h, const unsigned TOMS) {
  Send<S> send;
  Recv<S> recv { TOMS };
  if (send.req(sock, HOST, h.req())) {
    h.setres();
    if (recv.reqhdr(sock, h.header()) && recv.ischkd(h.header()))
      return recv.reqbody(sock, h.writercb());
    else if (const auto L { recv.parsecl(h.header()) }; L)
      return recv.reqbody(sock, h.writercb(), L);
    }

  return false;
}

template<typename S>
sockpp::MultiClient<S>::MultiClient(const char HOST[], const char PORT[], const unsigned N) : 
  HOST { std::string { HOST } } {
  if (N > MAXN)
    throw std::runtime_error("# of requested connexions exceeds supremum");
  
  for (auto i { 0U }; i < N; i++) {
    S &sock { SOCK[i] };
    if (sock.Http::init_client(HOST, PORT) && sock.connect(HOST)) {
      sock.init_poll();
      C[i] = 1;
    }
  }
  
  if (!C.any())
    throw std::runtime_error("Unable to connect");
}

template<typename S>
bool sockpp::MultiClient<S>::performreq(const std::vector<std::reference_wrapper<Handle::Xfr>> &H, const unsigned TOMS) {
  std::vector<SockH> SH;
  for (auto i { 0U }, j { 0U }; i < MAXN; i++)
    if (C[i])
      SH.emplace_back(SockH { SOCK[i], H[j++] });

  Send<S> send;
  for (auto sh { SH.begin() }; sh < SH.end();) {
    if (send.req(sh->sock.get(), HOST, sh->h.get().req())) {
      sh->h.get().setres();
      sh++;
    } else
        SH.erase(sh);
  }
  
  if (!SH.size())
    return false;

  Recv<S> recv { sockpp::MULTI_TOMS };
  Time time;
  const auto INITTIME { time.now() };
  while (SH.size() &&
    time.diffpt<std::chrono::milliseconds>(time.now(), INITTIME) < TOMS) {
    for (auto sh { SH.begin() }; sh < SH.end();)
      if (recv.reqhdr(sh->sock.get(), sh->h.get().header())) {
        if (recv.ischkd(sh->h.get().header()) && 
              recv.reqbody(sh->sock.get(), sh->h.get().writercb()));
        else if (const auto L { recv.parsecl(sh->h.get().header()) }; L &&
            recv.reqbody(sh->sock.get(), sh->h.get().writercb(), L));
        else
          continue;
        
        SH.erase(sh);
      } else
          sh++;
  }

  return true;
}

template<typename S>
sockpp::Server<S>::Server(const char PORT[]) {
  if (sock.Http::init_server(PORT))
    sock.init_poll();
  else
    throw std::runtime_error("Unable to init server");
}
// Construct a server for each client
template<>
void sockpp::Server<sockpp::Http>::recv_client(const char [], const char []) {
  auto server { std::make_unique<Http>(this->sock.accept()) };
  server->init_poll();
  SOCK.emplace_back(std::move(server));
}

template<>
void sockpp::Server<sockpp::Https>::recv_client(const char CERT[], const char KEY[]) {
  Https client;
  if (!client.init_client() || !client.configure_ctx(CERT, KEY))
    return;

  const auto FD { sock.Http::accept() };
  auto server { std::make_unique<Https>(FD) };
  if (server->init_server() && server->init()) {
    server->set_ctx(client.get_ctx());
    server->set_accept_state();
    if (server->set_fd(FD) && server->do_handshake() &&
      server->init_rbio() && server->init_wbio()) {
        server->set_rwbio();
        server->init_poll();
        SOCK.emplace_back(std::move(server));
    }
  }
}

template<typename S>
void sockpp::Server<S>::run(const Server_cb<S> &CB, const char CERT[], const char KEY[]) {
  while (!quit) {
    if (poll_listen(10))
      recv_client(CERT, KEY);
    
    for (auto i { 0U }; auto &sock : SOCK) {
      if (sock->pollin(10) && !CB(*sock)) {
        SOCK.erase(SOCK.begin() + i);
        break;
      }

      i++;
    }
  }
}
