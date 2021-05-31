#include <cstring>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/err.h>
#include <bitset>
#include "socket.h"

Http::Http(const float httpver, const std::string &hostname, const unsigned port) : 
  hostname(hostname), port(port)
{
  snprintf(this->httpver, sizeof this->httpver - 1, "%.1f", httpver);
  memset(&sa, 0, sizeof sa);
  if ((sd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    throw "Socket creation failed";
}

Http::~Http(void)
{
  struct linger lo { 1, 0 };
  setsockopt(sd, SOL_SOCKET, SO_LINGER, &lo, sizeof lo);
  close(sd);
}

bool Http::init_connect(void)
{
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);
  struct hostent *host { gethostbyname(hostname.c_str()) };
  if (!host)
  {
    report = "Unable to resolve hostname";
    return false;
  }

  sa.sin_addr.s_addr = *(long *) host->h_addr;
  return true;
}

Secure::Secure(const SSL_METHOD *meth)
{
  init_ssl(meth);
}

Secure::Secure(const SSL_METHOD *meth, const std::string &certpem) : certpem(certpem)
{
  init_ssl(meth);
}

Secure::Secure(const SSL_METHOD *meth, const std::string &certpem, const std::string &keypem) : certpem(certpem), keypem(keypem)
{
  init_ssl(meth);
}

Secure::~Secure(void)
{
  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
}

void Secure::init_ssl(const SSL_METHOD *meth)
{
  if (!(ctx = SSL_CTX_new(meth)))
    throw "Unable to create context";
  else if (!(ssl = SSL_new(ctx)))
    throw "Unable to create ssl";
}

void Secure::gather_certificate(std::string &report)
{
  // Method to be called after connector()
  cipherinfo = std::string(SSL_get_cipher(ssl));
  X509 *server_cert { SSL_get_peer_certificate(ssl) };
  if (!server_cert)
    report = "[SSL] Allocation failure server_cert";

  char *certificate { X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0) };
  if (!certificate)
    report = "[SSL] Allocation failure certificate string";
  else
  {
    this->certificate = std::string(certificate);
    OPENSSL_free(certificate);
  }

  char *issuer { X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0) };
  if (!issuer)
    report = "[SSL] Allocation failure issuer string";
  else
  {
    this->issuer = std::string(issuer);
    OPENSSL_free(issuer);
  }

  if (server_cert)
    X509_free(server_cert);
}

bool Secure::configure_context(std::string &report)
{
  SSL_CTX_set_ecdh_auto(ctx, 1);
  ssize_t err;
  if ((err = SSL_CTX_use_certificate_file(ctx, certpem.c_str(), SSL_FILETYPE_PEM)) < 1)
  {
    report = "[SSL] configure_context(): " + std::to_string(SSL_get_error(ssl, err));
    return false;
  }
  if (keypem.size() && (err = SSL_CTX_use_PrivateKey_file(ctx, keypem.c_str(), SSL_FILETYPE_PEM)) < 1)
  {
    report = "[SSL] configure_context(): " + std::to_string(SSL_get_error(ssl, err));
    return false;
  }
  else if (!keypem.size() && (err = SSL_CTX_use_PrivateKey_file(ctx, certpem.c_str(), SSL_FILETYPE_PEM)) < 1)
  {
    report = "[SSL] configure_context(): " + std::to_string(SSL_get_error(ssl, err));
    return false;
  }

  return true;
}

int Secure::set_tlsext_hostname(const std::string &hostname)
{
  return SSL_set_tlsext_host_name(ssl, hostname.c_str());
}

int Secure::set_fd(const int fd)
{
  return SSL_set_fd(ssl, fd);
}

int Secure::connect(void)
{
  return SSL_connect(ssl);
}

int Secure::get_error(int err)
{
  return SSL_get_error(ssl, err);
}

int Secure::read(void *buf, int size)
{
  return SSL_read(ssl, buf, size);
}

int Secure::write(const std::string &data)
{
  return SSL_write(ssl, data.c_str(), data.size());
}

int Secure::accept(void)
{
  return SSL_accept(ssl);
}

SSL_CTX *Secure::set_CTX(const Secure &secure)
{
  return SSL_set_SSL_CTX(ssl, secure.ctx);
}

int Secure::clear(void)
{
  return SSL_clear(ssl);
}

SecureClient::SecureClient(void) : Secure(TLS_client_method())
{

}

SecureServer::SecureServer(void) : Secure(TLS_server_method())
{

}

Client::Client(const float httpver, const std::string &hostname, const unsigned port) : 
  Http(httpver, hostname, port)
{

}

Client::~Client(void)
{

}

bool Client::connect(void)
{
  if (!init_connect())
    return false;
  return connector();
}

bool Client::sendreq(const std::vector<std::string> &H, const std::string &data)
{
  std::string request;
  for (auto &h : H)
    request += h + "\r\n";

  if (data.size())
    request += "Content-Length: " + std::to_string(data.size()) + "\r\n\r\n" + data;

  request += "\r\n";
  return writer(request);
}

bool Client::sendreq(const REQ req, const std::string &endp, const std::vector<std::string> &H, const std::string &data)
{
  std::string req_type { 
    req == GET ? "GET" : 
    req == POST ? "POST" : 
    req == PUT ? "PUT" : 
    req == DELETE ? "DELETE" : 
    std::string() 
  };

  if (!req_type.size())
  {
    report = "Bad request type";
    return false;
  }

  std::string request { 
    req_type + " " + endp + " " + "HTTP/" + std::string(httpver) + "\r\n" +
    "Host: " + hostname + "\r\n" +
    "User-Agent: " + agent + "\r\n" +
    "Accept: */*" + "\r\n" };

  for (auto &h : H)
    request += h + "\r\n";

  if (data.size())
    request += "Content-Length: " + std::to_string(data.size()) + "\r\n\r\n" + data;

  request += "\r\n";
  return writer(request);
}

bool Client::recvreq(void)
{
  response_header.clear();
  response_body.clear();
  // Response Header
  char p;
  bool res;
  do
  {
    res = reader(p);
    response_header += p;
  }
  while (res && !(response_header.rfind("\r\n\r\n") < std::string::npos));
  
  if (!std::regex_search(response_header, match, ok_regex))
  {
    report = response_header.substr(match.prefix().length(), response_header.rfind("\r\n"));
    return 0;
  }

  // Response Body
  std::size_t l { };
  if (std::regex_search(response_header, match, content_length_regex) &&
      (l = std::stoull(response_header.substr(match.prefix().length() + 16,
        response_header.substr(match.prefix().length() + 16).find("\r\n")))))
    do
    {
      res = reader(p);
      response_body += p;
    }
    while (res && response_body.size() < l);

  else if (std::regex_search(response_header, match, transfer_encoding_regex) &&
      std::regex_match(response_header.substr(match.prefix().length() + 19, 7), chunked_regex))
  {
    auto now { this->now() };
    while (reader(p) && diffpt(this->now(), now) < timeout)
    {
      response_body += p;
      now = this->now();
      if (response_body == "\r\n");
      else if (!l && response_body.rfind("\r\n") < std::string::npos)
      {
        response_body.erase(response_body.end() - 2, response_body.end());
        if (!(l = std::stoull(response_body, nullptr, 16)))
          break;
      }
      else if (response_body.size() == l)
      {
        response_cb(response_body);
        l = 0;
      }
      else
        continue;

      response_body.clear();
    }
  }

  return 1;
}

void Client::recvreq_raw(void)
{
  char p;
  auto now { this->now() };
  while (reader(p) && diffpt(this->now(), now) < timeout)
  {
    response_body += p;
    now = this->now();
    response_cb(response_body);
    response_body.clear();
  }
}

bool Client::performreq(const std::vector<std::string> &H, const std::string &data)
{
  if (connect())
  {
    if (!sendreq(H, data))
      return false;

    return recvreq();
  }

  return false;
}

bool Client::performreq(const REQ req, const std::string &endp, const std::vector<std::string> &H, const std::string &data)
{
  if (connect())
  {
    if (!sendreq(req, endp, H, data))
      return false;
    
    return recvreq();
  }

  return false;
}

HttpClient::HttpClient(const float httpver, const std::string &hostname, const unsigned port) : 
  Client(httpver, hostname, port)
{
  connector = [&](void) -> bool { 
    if (::connect(sd, (struct sockaddr *) &sa, sizeof sa) < 0)
    {
      report = "Connect error";
      return false;
    }
    return true;
  };

  reader = [&](char &p) -> bool {
    if (::recv(sd, &p, sizeof p, 0) < 0)
    {
      report = "Read error";
      return false;
    }
    return true;
  };

  writer = [&](const std::string &request) -> bool { 
    if (::write(sd, request.c_str(), request.size()) < 0)
    {
      report = "Write error";
      return false;
    }
    return true;
  };
}

HttpClient::~HttpClient(void)
{

}

HttpsClient::HttpsClient(const float httpver, const std::string &hostname, const unsigned port) : 
  Client(httpver, hostname, port)
{
  OpenSSL_add_ssl_algorithms();
  SSL_load_error_strings();
  connector = [&](void) -> bool {
    if (::connect(sd, (struct sockaddr *) &sa, sizeof sa) < 0)
    {
      report = "Connect error";
      return false;
    }

    sslclient.configure_context(report);
    sslclient.set_tlsext_hostname(hostname);
    sslclient.set_fd(sd);
    if ((err = sslclient.connect()) < 0)
    {
      report = "[SSL] Connect: " + std::to_string(sslclient.get_error(err));
      return false;
    }

    return true;
  };

  reader = [&](char &p) -> bool {
    if ((err = sslclient.read(&p, sizeof p)) < 0)
    {
      report = "Read: " + std::to_string(sslclient.get_error(err));
      return false;
    }

    return true;
  };

  writer = [&](const std::string &request) -> bool {
    if ((err = sslclient.write(request)) < 0)
    {
      report = "Write: " + std::to_string(sslclient.get_error(err));
      return false;
    }

    return true;
  };
}

HttpsClient::~HttpsClient(void)
{

}

MultiClient::MultiClient(void)
{

}

bool MultiClient::set_client(Client &c)
{
  if (C.size() < MAX_CLIENTS)
  {
    C.emplace_back(c);
    return true;
  }

  return false;
}

bool MultiClient::connect(void)
{
  bool retval { true };
  for (auto &c : C)
    if (!c.get().connect())
      retval = false;

  return retval;
}

void MultiClient::recvreq(unsigned timeout_ms)
{
  struct pollfd PFD[MAX_CLIENTS] { };
  std::bitset<MAX_CLIENTS> M;
  for (auto i { 0U }; i < C.size(); i++)
  {
    PFD[i].fd = C[i].get().sd;
    PFD[i].events = POLLIN;
  }

  const auto init { this->now() };
  auto now { init };
  while (M.count() < C.size() && diffpt(now, init) < timeout)
  {
    poll(PFD, C.size(), timeout_ms);
    for (auto i { 0U }; i < C.size(); i++)
      if (PFD[i].revents & POLLIN && !M[i])
      {
        C[i].get().recvreq();
        M |= 1 << i;
      }

    now = this->now();
  }
}

Server::Server(const float httpver, const std::string &hostname, const unsigned port) : Http(httpver, hostname, port)
{

}

bool Server::connect(void)
{
  if (!init_connect())
    return false;

  if (::bind(sd, (struct sockaddr *) &sa, sizeof sa) < 0)
  {
    report = "Unable to bind. Check server address if already in use.";
    close(sd);
    return false;
  }

  if (::listen(sd, 1) < 0)
  {
    report = "Unable to listen";
    return false;
  }

  listensd.fd = sd;
  listensd.events = POLLIN;
  return true;
}

bool Server::poll_listen(unsigned timeout_ms)
{
  poll(&listensd, 1, timeout_ms);
  if (listensd.revents & POLLIN)
    return true;

  return false;
}

int Server::recv_client(void)
{
  struct sockaddr_in addr;
  uint len { sizeof addr };
  return accept(sd, (struct sockaddr *) &addr, &len);
}

void Server::new_client(const std::function<void(const std::any)> &cb, std::any arg)
{
  auto c { std::async(std::launch::async, [=] { cb(arg); }) };
  C.emplace_back(std::move(c));
}

void Server::refresh_clients(void)
{
  C.remove_if([](auto &c) { 
    return c.wait_for(std::chrono::milliseconds(1)) == std::future_status::ready; });
}

bool Server::close_client(int clientsd)
{
  if (close(clientsd) > -1)
    return true;

  return false;
}

HttpServer::HttpServer(const std::string &hostname, const unsigned port) :
  Server(DEFAULT_HTTPVER, hostname, port)
{

}

HttpServer::~HttpServer(void)
{

}

void HttpServer::recvreq(std::string &document, int clientsd)
{
  char p;
  std::string header, body;
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

  document = header + body;
}

bool HttpServer::write(const int clientsd, const std::string &document)
{
  if (::write(clientsd, document.c_str(), document.size()) < 0)
    return false;

  fsync(clientsd);
  return true;
}

HttpsServer::HttpsServer(const std::string &hostname, const unsigned port) :
  Server(DEFAULT_HTTPVER, hostname, port)
{
  OpenSSL_add_ssl_algorithms();
  SSL_load_error_strings();
}

HttpsServer::~HttpsServer(void)
{

}

SecurePair HttpsServer::recv_client(std::string &report)
{
  auto clientsd { Server::recv_client() };
  try {
    SecureClient client;
    if (!client.configure_context(report))
    {
      report = "Configure client context: " + report;
      close(clientsd);
      return { -1 };
    }

    client.set_tlsext_hostname(hostname);
    SecurePair pair { clientsd, std::make_unique<SecureServer>() };
    pair.sslserver->set_fd(clientsd);
    pair.sslserver->set_CTX(client);
    ssize_t err;
    if ((err = pair.sslserver->accept()) < 1)
    {
      report = "[SSL] accept(): " + std::to_string(client.get_error(err));
      return { -1 };
    }

    return pair;
  }

  catch (const std::string &e) {
    report = e;
  }

  return { -1 };
}
