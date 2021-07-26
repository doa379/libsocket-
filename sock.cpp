#include <cstring>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/err.h>
#include <bitset>
#include "sock.h"

Sock::Sock(const int sd)
{
  init(sd);
  memset(&sa, 0, sizeof sa);
}

Sock::~Sock(void)
{
  deinit();
}

bool Sock::init(const int sd)
{
  if (sd)
    this->sd = sd;
  else if ((this->sd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    return false;

  return true;
}

void Sock::deinit(void)
{
  struct linger lo { 1, 0 };
  setsockopt(sd, SOL_SOCKET, SO_LINGER, &lo, sizeof lo);
  close(sd);
}

bool Sock::init_connect(const std::string &hostname, const unsigned port)
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

bool Sock::connect(void)
{
  if (::connect(sd, (struct sockaddr *) &sa, sizeof sa) > -1)
    return true;
  return false;
}

bool Sock::read(char &p)
{
  if (::recv(sd, &p, sizeof p, 0) > -1)
    return true;
  return false;
}

bool Sock::write(const std::string &data)
{
  if (::write(sd, data.c_str(), data.size()) > -1)
  {
    fsync(sd);
    return true;
  }
  return false;
}

int Sock::accept(void)
{
  struct sockaddr_in addr;
  uint len { sizeof addr };
  return ::accept(sd, (struct sockaddr *) &addr, &len);
  // Return a sd
}
  
bool Sock::bind(void)
{
  if (::bind(sd, (struct sockaddr *) &sa, sizeof sa) > -1)
    return true;

  return false;
}

bool Sock::listen(void)
{
  if (::listen(sd, 1) > -1)
    return true;

  return false;
}

InitSocks::InitSocks(void)
{
  InitSocks::init();
}

void InitSocks::init(void)
{
  OpenSSL_add_ssl_algorithms();
  SSL_load_error_strings();
}

Socks::Socks(const SSL_METHOD *meth, const std::string &hostname, const std::string &certpem, const std::string &keypem, const unsigned sd) : 
  Sock(sd),
  ctx(SSL_CTX_new(meth)), ssl(SSL_new(ctx)), hostname(hostname), certpem(certpem), keypem(keypem)
{
  if (!ctx)
    throw "Unable to create context";
  else if (!ssl)
    throw "Unable to create ssl";
}

Socks::~Socks(void)
{
  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
}

bool Socks::configure_context(void)
{
  SSL_CTX_set_ecdh_auto(ctx, 1);
  ssize_t err;
  if ((err = SSL_CTX_use_certificate_file(ctx, certpem.c_str(), SSL_FILETYPE_PEM)) < 1)
  {
    //report = "[SSL] configure_context(): " + std::to_string(SSL_get_error(ssl, err));
    return false;
  }
  if (keypem.size() && (err = SSL_CTX_use_PrivateKey_file(ctx, keypem.c_str(), SSL_FILETYPE_PEM)) < 1)
  {
    //report = "[SSL] configure_context(): " + std::to_string(SSL_get_error(ssl, err));
    return false;
  }
  else if (!keypem.size() && (err = SSL_CTX_use_PrivateKey_file(ctx, certpem.c_str(), SSL_FILETYPE_PEM)) < 1)
  {
    //report = "[SSL] configure_context(): " + std::to_string(SSL_get_error(ssl, err));
    return false;
  }

  return true;
}

bool Socks::set_hostname(void)
{
  if (SSL_set_tlsext_host_name(ssl, hostname.c_str()) > 0)
    return true;
  return false;
}

bool Socks::set_fd(void)
{
  if (SSL_set_fd(ssl, sd) > 0)
    return true;
  return false;
}

/*
bool Socks::connect(void)
{
  if (SSL_connect(ssl) > 0)
    return true;

  return false;
}
*/
bool Socks::connect(void)
{
    /*
  connector = [&, this, certpem, keypem](void) -> bool {
    if (::connect(sd, (struct sockaddr *) &sa, sizeof sa) < 0)
    {
      _report = "Connect error";
      return false;
    }
    

    sslclient.configure_context(_report, certpem, keypem);
    sslclient.set_tlsext_hostname(this->hostname);
    sslclient.set_fd(sd);
    if ((err = sslclient.connect()) > 0)
      return true;
    _report = "[SSL] Connect: " + std::to_string(sslclient.error(err));
    return false;
  };
  */

  if (Sock::connect())
  {
    configure_context();
    set_hostname();
    set_fd();
    if (SSL_connect(ssl) > 0)
      return true;
  }

  return false;
}

bool Socks::read(char &p)
{
  if (SSL_read(ssl, &p, sizeof p) > 0)
    return true;
  return false;
}

bool Socks::write(const std::string &data)
{
  if (SSL_write(ssl, data.c_str(), data.size()) > 0)
    return true;
  return false;
}
/*
int Secure::error(int err)
{
  return SSL_get_error(ssl, err);
}
*/
bool Socks::clear(void)
{
  if (SSL_clear(ssl) > 0)
    return true;

  return false;
}
/*
SocksServer::SocksServer(const SSL_METHOD *meth, const std::string &hostname, const std::string &certpem, const std::string &keypem) : 
  Socks(meth, hostname, certpem, keypem)
{

}
*/
bool Socks::accept(void)
{
  if (SSL_accept(ssl) > 0)
    return true;
  return false;
}

SSL_CTX *Socks::set_ctx(SSL_CTX *ctx)
{
  return SSL_set_SSL_CTX(ssl, ctx);
}


/*
void Secure::gather_certificate(std::string &report)
{
  // Method to be called after connector()
  _cipherinfo = std::string(SSL_get_cipher(ssl));
  X509 *server_cert { SSL_get_peer_certificate(ssl) };
  if (!server_cert)
    report = "[SSL] Allocation failure server_cert";

  char *certificate { X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0) };
  if (!certificate)
    report = "[SSL] Allocation failure certificate string";
  else
  {
    _certificate = std::string(certificate);
    OPENSSL_free(certificate);
  }

  char *issuer { X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0) };
  if (!issuer)
    report = "[SSL] Allocation failure issuer string";
  else
  {
    _issuer = std::string(issuer);
    OPENSSL_free(issuer);
  }

  if (server_cert)
    X509_free(server_cert);
}
*/


/*
int SecureClient::read(void *buf, int size)
{
  return SSL_read(ssl, buf, size);
}

SecureServer::SecureServer(void) : Secure(TLS_server_method())
{

}

SSL_CTX *SecureServer::set_CTX(SSL_CTX *ctx)
{
  return SSL_set_SSL_CTX(ssl, ctx);
}

int SecureServer::accept(void)
{
  return SSL_accept(ssl);
}
*/
template<typename T>
bool Recv::req(T &sock, const Cb &cb)
{
  clear_header();
  clear_body();
  // Header
  char p;
  bool res;
  do
  {
    res = sock.read(p);
    _header += p;
  }
  while (res && !(_header.rfind("\r\n\r\n") < std::string::npos));
  
  if (!std::regex_search(_header, match, ok_regex))
    return false;
  // Body
  std::size_t l { };
  if (std::regex_search(_header, match, content_length_regex) &&
      (l = std::stoull(_header.substr(match.prefix().length() + 16,
        _header.substr(match.prefix().length() + 16).find("\r\n")))))
    do
    {
      res = sock.read(p);
      _body += p;
    }
    while (res && _body.size() < l);

  else if (std::regex_search(_header, match, transfer_encoding_regex) &&
      std::regex_match(_header.substr(match.prefix().length() + 19, 7), chunked_regex))
  {
    auto now { time.now() };
    while (sock.read(p) && time.diffpt<std::chrono::milliseconds>(time.now(), now) < timeout_ms)
    {
      _body += p;
      now = time.now();
      if (_body == "\r\n");
      else if (!l && _body.rfind("\r\n") < std::string::npos)
      {
        _body.erase(_body.end() - 2, _body.end());
        if (!(l = std::stoull(_body, nullptr, 16)))
          break;
      }
      else if (_body.size() == l)
      {
        cb(_body);
        l = 0;
      }
      else
        continue;

      _body.clear();
    }
  }

  return true;
}

template<typename T>
void Recv::req_raw(T &sock, const Cb &cb)
{
  char p;
  auto now { time.now() };
  while (sock.read(p) && time.diffpt<std::chrono::milliseconds>(time.now(), now) < timeout_ms)
  {
    _body += p;
    now = time.now();
    cb(_body);
    clear_body();
  }
}

template<>
Client<Sock>::Client(const float httpver, const std::string &hostname, const unsigned port, const std::string &, const std::string &) : 
  sock(std::make_unique<Sock>()), hostname(hostname), port(port)
{
  snprintf(this->httpver, sizeof this->httpver - 1, "%.1f", httpver);
}

template<>
Client<Socks>::Client(const float httpver, const std::string &hostname, const unsigned port, const std::string &certpem, const std::string &keypem) : 
  sock(std::make_unique<Socks>(TLS_client_method(), hostname, certpem, keypem)), hostname(hostname), port(port)
{
  snprintf(this->httpver, sizeof this->httpver - 1, "%.1f", httpver);
}

template<typename T>
bool Client<T>::connect(void)
{
  if (sock->init_connect(hostname, port))
    return sock->connect();
  
  return false;
}

template<typename T>
bool Client<T>::sendreq(const std::vector<std::string> &H, const std::string &data)
{
  std::string request;
  for (auto &h : H)
    request += h + "\r\n";

  if (data.size())
    request += "Content-Length: " + std::to_string(data.size()) + "\r\n\r\n" + data;

  request += "\r\n";
  return sock->write(request);
}

template<typename T>
bool Client<T>::sendreq(const unsigned req, const std::string &endp, const std::vector<std::string> &H, const std::string &data)
{
  if (&REQ[req] > &REQ[REQ.size() - 1]
    || (req == GET && data.size()))
    return false;

  std::string request { 
    REQ[req] + " " + endp + " " + "HTTP/" + std::string(httpver) + "\r\n" +
    "Host: " + hostname + "\r\n" +
    "User-Agent: " + std::string(agent) + "\r\n" +
    "Accept: */*" + "\r\n" };

  for (auto &h : H)
    request += h + "\r\n";

  if (data.size())
    request += "Content-Length: " + std::to_string(data.size()) + "\r\n\r\n" + data;

  request += "\r\n";
  return sock->write(request);
}

template<typename T>
bool Client<T>::performreq(const Cb &cb, const std::vector<std::string> &H, const std::string &data)
{
  if (sock->connect() && sendreq(H, data))
    return this->req(cb);

  return false;
}

template<typename T>
bool Client<T>::performreq(const unsigned req, const Cb &cb, const std::string &endp, const std::vector<std::string> &H, const std::string &data)
{
  if (sock->connect() && sendreq(req, endp, H, data))
    return this->req(cb);

  return false;
}

template class Client<Sock>;
template class Client<Socks>;

/*
HttpClient::HttpClient(const float httpver, const std::string &hostname, const unsigned port) : 
  Client(httpver, hostname, port)
{
  connector = [&](void) -> bool { 
    if (::connect(sd, (struct sockaddr *) &sa, sizeof sa) > -1)
      return true;
    _report = "Connect error";
    return false;
  };

  reader = [&](char &p) -> bool {
    if (::recv(sd, &p, sizeof p, 0) > -1)
      return true;
    _report = "Read error";
    return false;
  };

  writer = [&](const std::string &request) -> bool { 
    if (::write(sd, request.c_str(), request.size()) > -1)
      return true;
    _report = "Write error";
    return false;
  };
}

HttpClient::~HttpClient(void)
{

}
*/
/*
HttpsClient::HttpsClient(const float httpver, const std::string &hostname, const unsigned port, const std::string &certpem, const std::string &keypem) :
  Client(httpver, hostname, port)
{
  connector = [&, this, certpem, keypem](void) -> bool {
    if (::connect(sd, (struct sockaddr *) &sa, sizeof sa) < 0)
    {
      _report = "Connect error";
      return false;
    }

    sslclient.configure_context(_report, certpem, keypem);
    sslclient.set_tlsext_hostname(this->hostname);
    sslclient.set_fd(sd);
    if ((err = sslclient.connect()) > 0)
      return true;
    _report = "[SSL] Connect: " + std::to_string(sslclient.error(err));
    return false;
  };

  reader = [&](char &p) -> bool {
    if ((err = sslclient.read(&p, sizeof p)) > 0)
      return true;
    _report = "Read: " + std::to_string(sslclient.error(err));
    return false;
  };

  writer = [&](const std::string &request) -> bool {
    if ((err = sslclient.write(request)) > 0)
      return true;
    _report = "Write: " + std::to_string(sslclient.error(err));
    return false;
  };
}
*/

template<typename T>
bool MultiClient<T>::set_client(Client<T> &c)
{
  if (C.size() < MAX_CLIENTS)
  {
    C.emplace_back(c);
    return true;
  }

  return false;
}

template<typename T>
bool MultiClient<T>::connect(void)
{
  bool retval { true };
  for (auto &c : C)
    if (!c.get().connect())
      retval = false;

  return retval;
}

template<typename T>
void MultiClient<T>::recvreq(unsigned timeout)
{
  struct pollfd PFD[MAX_CLIENTS] { };
  std::bitset<MAX_CLIENTS> M;
  for (auto i { 0U }; i < C.size(); i++)
  {
    PFD[i].fd = C[i].get().sock->get();
    PFD[i].events = POLLIN;
  }

  const auto init { time.now() };
  auto now { init };
  while (M.count() < C.size() && time.diffpt<std::chrono::seconds>(now, init) < timeout)
  {
    poll(PFD, C.size(), 100);
    for (auto i { 0U }; i < C.size(); i++)
      if (PFD[i].revents & POLLIN && !M[i])
      {
        C[i].get().req();
        M |= 1 << i;
      }

    now = time.now();
  }
}

template class MultiClient<Sock>;
template class MultiClient<Socks>;

template<>
Server<Sock>::Server(const std::string &hostname, const unsigned port, const std::string &, const std::string &) :
  sock(std::make_unique<Sock>()), hostname(hostname), port(port)
{

}

template<>
Server<Socks>::Server(const std::string &hostname, const unsigned port, const std::string &certpem, const std::string &keypem) :
  sock(std::make_unique<Socks>(TLS_server_method(), hostname, certpem, keypem)), hostname(hostname), port(port)
{

}

template<typename T>
bool Server<T>::connect(void)
{
  if (!sock->init_connect(hostname, port))
    return false;
  if (!sock->bind())
  {
    sock->deinit();
    return false;
  }
  if (!sock->listen())
    return false;
    /*
  if (::bind(sd, (struct sockaddr *) &sa, sizeof sa) < 0)
  {
    _report = "Unable to bind. Check server address if already in use";
    close(sd);
    return false;
  }

  if (::listen(sd, 1) < 0)
  {
    _report = "Unable to listen";
    return false;
  }
*/
  listensd.fd = sock->get();
  listensd.events = POLLIN;
  return true;
}

template<typename T>
bool Server<T>::poll_listen(unsigned timeout_ms)
{
  poll(&listensd, 1, timeout_ms);
  if (listensd.revents & POLLIN)
    return true;

  return false;
}

template<>
std::shared_ptr<Sock> Server<Sock>::recv_client(const std::string &, const std::string &)
{
  return std::make_shared<Sock>(this->sock->accept());
}

template<>
std::shared_ptr<Socks> Server<Socks>::recv_client(const std::string &certpem, const std::string &keypem)
{
  //auto clientsd { Server::recv_client() };
  auto client { std::make_shared<Socks>(TLS_client_method(), hostname, certpem, keypem) };
  client->configure_context();
  client->set_hostname();
  auto sd { sock->Sock::accept() };
  auto socks { std::make_shared<Socks>(TLS_server_method(), hostname, certpem, keypem, sd) };
  socks->set_fd();
  socks->set_ctx(client->get_ctx());
  if (socks->accept())
    return socks;

  return nullptr;

/*
  try {
    SecureClient client;
    if (!client.configure_context(report, certpem, keypem))
    {
      report = "Configure client context: " + report;
      close(clientsd);
      return { -1 };
    }

    client.set_tlsext_hostname(hostname);
    SecurePair pair { clientsd, std::make_unique<SecureServer>() };
    pair.sslserver->set_fd(clientsd);
    pair.sslserver->set_CTX(client.ctx());
    ssize_t err;
    if ((err = pair.sslserver->accept()) < 1)
    {
      report = "[SSL] accept(): " + std::to_string(client.error(err));
      return { -1 };
    }

    return pair;
  }

  catch (const std::string &e) {
    report = e;
  }

  return { -1 };
  */
}

template<typename T>
void Server<T>::new_client(std::shared_ptr<T> t, const std::function<void(T &)> &cb)
{
  auto c { std::async(std::launch::async, [=](void) mutable { cb(*t); }) };
  C.emplace_back(std::move(c));
}

template<typename T>
void Server<T>::refresh_clients(void)
{
  C.remove_if([](auto &c) { 
    return c.wait_for(std::chrono::milliseconds(1)) == std::future_status::ready; });
}

template class Server<Sock>;
template class Server<Socks>;
/*
bool Server::close_client(int clientsd)
{
  if (close(clientsd) > -1)
    return true;

  return false;
}

*/
/*
SockServer::SockServer(const std::string &hostname, const unsigned port) :
  Server(sock, hostname, port)
{

}

SockServer::~SockServer(void)
{

}
*/
/*
void HttpServer::recvreq(int clientsd)
{
  header.clear();
  body.clear();
  char p;
  do
  {
    if (::recv(clientsd, &p, sizeof p, 0) < 0)
      break;
    header += p;
  }
  while (!(header.rfind("\r\n\r\n") < std::string::npos));

  std::size_t l { };
  if (std::regex_search(header, match, content_length_regex) &&
      (l = std::stoull(header.substr(match.prefix().length() + 16,
        header.substr(match.prefix().length() + 16).find("\r\n")))))
    do
    {
      if (::recv(clientsd, &p, sizeof p, 0) < 0)
        break;
      body += p;
    }
    while (body.size() < l);
}

bool HttpServer::write(const int clientsd, const std::string &document)
{
  if (::write(clientsd, document.c_str(), document.size()) < 0)
    return false;

  fsync(clientsd);
  return true;
}
*/
/*
HttpsServer::HttpsServer(const std::string &hostname, const unsigned port) :
  Server(DEFAULT_HTTPVER, hostname, port)
{

}

HttpsServer::~HttpsServer(void)
{

}

SecurePair HttpsServer::recv_client(std::string &report, const std::string &certpem, const std::string &keypem)
{
  auto clientsd { Server::recv_client() };
  try {
    SecureClient client;
    if (!client.configure_context(report, certpem, keypem))
    {
      report = "Configure client context: " + report;
      close(clientsd);
      return { -1 };
    }

    client.set_tlsext_hostname(hostname);
    SecurePair pair { clientsd, std::make_unique<SecureServer>() };
    pair.sslserver->set_fd(clientsd);
    pair.sslserver->set_CTX(client.ctx());
    ssize_t err;
    if ((err = pair.sslserver->accept()) < 1)
    {
      report = "[SSL] accept(): " + std::to_string(client.error(err));
      return { -1 };
    }

    return pair;
  }

  catch (const std::string &e) {
    report = e;
  }

  return { -1 };
}
*/
