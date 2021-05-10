#include <cstring>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <iostream>
#include <openssl/err.h>
#include <sys/poll.h>
#include <bitset>
#include <thread>
#include "socket.h"

Http::Http(const float httpver, const std::string &hostname, const unsigned port) : 
  hostname(hostname), port(port)
{
  snprintf(this->httpver, sizeof this->httpver - 1, "%.1f", httpver);
  memset(&sa, 0, sizeof sa);
  try {
    sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd < 0)
      throw "Socket creation failed";
  }
  catch(const std::string &ex) {
    report = ex;
    throw;
  }
}

Http::~Http(void)
{
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

Secure::Secure(void) : certpem(CERTPEM), keypem(KEYPEM)
{

}

Secure::Secure(const std::string &certpem) : certpem(certpem)
{

}

Secure::Secure(const std::string &certpem, const std::string &keypem) : certpem(certpem), keypem(keypem)
{

}

void Secure::deinit_ssl(void)
{
  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
}

SecureClientPair::SecureClientPair(void)
{
  try {
    const SSL_METHOD *meth { TLS_client_method() };
    ctx = SSL_CTX_new(meth);
    ssl = SSL_new(ctx);
    if (!ctx)
      throw "context";
    else if (!ssl)
      throw "ssl";
  }
  catch(const std::string &ex) {
    std::cerr << "Unable to create " + ex + '\n';
    throw;
  }
}

SecureClientPair::~SecureClientPair(void)
{
  deinit_ssl();
}

SecureServerPair::SecureServerPair(void)
{
  try {
    const SSL_METHOD *meth { TLS_server_method() };
    ctx = SSL_CTX_new(meth);
    ssl = SSL_new(ctx);
    if (!ctx)
      throw "context";
    else if (!ssl)
      throw "ssl";
  }
  catch(const std::string &ex)
  {
    std::cerr << "Unable to create " + ex + '\n';
    throw;
  }
}

SecureServerPair::~SecureServerPair(void)
{
  deinit_ssl();
}

void Secure::gather_certificate(void)
{
  // Method to be called after connector()
  cipherinfo = std::string(SSL_get_cipher(ssl));
  try {
    X509 *server_cert { SSL_get_peer_certificate(ssl) };
    if (!server_cert)
      throw "server_cert";

    char *certificate { X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0) };
    if (!certificate)
      throw "certificate string";
    else
    {
      this->certificate = std::string(certificate);
      OPENSSL_free(certificate);
    }

    char *issuer { X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0) };
    if (!issuer)
      throw "issuer string";
    else
    {
      this->issuer = std::string(issuer);
      OPENSSL_free(issuer);
    }

    if (server_cert)
      X509_free(server_cert);
  }

  catch(std::string &ex)
  {
    std::cerr << "Allocation failure: " + ex + '\n';
  }
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

bool Client::sendreq(const std::vector<std::string> &HEADERS, const std::string &data)
{
  std::string request;
  for (auto &h : HEADERS)
    request += h + "\r\n";

  if (data.size())
    request += "Content-Length: " + std::to_string(data.size()) + "\r\n\r\n" + data;

  request += "\r\n";
  return writer(request);
}

bool Client::sendreq(REQUEST req, const std::string &endp, const std::vector<std::string> &H, const std::string &data)
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
    report = "Unknown request type";
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

void Client::recvreq(void)
{
  response_header.clear();
  response_body.clear();
  char p;
  bool res;
  do
  {
    res = reader(p);
    response_header += p;
  }
  while (res && !(response_header.find("\r\n\r\n") < std::string::npos));

  std::size_t l { };
  if (std::regex_search(response_header, match, content_length_regex) &&
      (l = std::stoull(response_header.substr(match.prefix().length() + 16))))
    do
    {
      res = reader(p);
      response_body += p;
    }
    while (res && response_body.size() < l);

  else
  {
    auto now { this->now() };
    while (reader(p) && difftime(this->now(), now) < timeout)
    {
      response_body += p;
      now = this->now();
      if (response_body == "\r\n");
      else if (!l && response_body.find("\r\n") < std::string::npos)
        l = std::stoull(response_body, nullptr, 16);
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
}

void Client::recvreq_raw(void)
{
  char p;
  auto now { this->now() };
  while (reader(p) && difftime(this->now(), now) < timeout)
  {
    response_body += p;
    now = this->now();
    response_cb(response_body);
    response_body.clear();
  }
}

HttpClient::HttpClient(const float httpver, const std::string &hostname, const unsigned port) : 
  Client(httpver, hostname, port)
{
  connector = [this](void) -> bool { 
    if (::connect(sd, (struct sockaddr *) &sa, sizeof sa) < 0)
    {
      report = "Connect error";
      return false;
    }
    return true;
  };
  reader = [this](char &p) -> bool {
    if (::recv(sd, &p, sizeof p, 0) < 1)
    {
      report = "Read error";
      return false;
    }
    return true;
  };
  writer = [this](const std::string &request) -> bool { 
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
  connector = [this](void) -> bool {
    if (::connect(sd, (struct sockaddr *) &sa, sizeof sa) < 0)
    {
      report = "Connect error";
      return false;
    }
    sslclient.configure_context(report);
    sslclient.set_tlsext_hostname(this->hostname);
    sslclient.set_fd(sd);
    ssize_t err;
    if ((err = sslclient.connect()) < 0)
    {
      err = sslclient.get_error(err);
      report = "[SSL] Connect: " + std::to_string(sslclient.get_error(err));
      return false;
    }
    return true;
  };
  reader = [this](char &p) -> bool {
    ssize_t err { sslclient.read(&p, sizeof p) };
    if (err < 1)
    {
      report = "Read: " + std::to_string(sslclient.get_error(err));
      return false;
    }
    return true;
  };
  writer = [this](const std::string &request) -> bool {
    ssize_t err;
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

void MultiClient::recvreq(void)
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
  while (M.count() < C.size() && difftime(now, init) < timeout)
  {
    for (auto i { 0U }; i < C.size(); i++)
      if (PFD[i].revents & POLLIN && !M[i])
      {
        C[i].get().recvreq();
        M |= 1 << i;
      }

    now = this->now();
    poll(PFD, C.size(), WAITMS);
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
    report = "Unable to bind";
    return false;
  }
  if (::listen(sd, 1) < 0)
  {
    report = "Unable to listen";
    return false;
  }

  return true;
}

HttpServer::HttpServer(const std::string &hostname, const unsigned port) :
  Server(DEFAULT_HTTPVER, hostname, port)
{

}

HttpServer::~HttpServer(void)
{

}

bool HttpServer::write(const int clientsd, const std::string &document)
{
  if (::write(clientsd, document.c_str(), document.size()) < 0)
    return false;

  return true;
}

bool HttpServer::run(const std::function<void(const int)> &cb)
{
  while (1)
  {
    struct sockaddr_in addr;
    uint len { sizeof addr };
    int clientsd { accept(sd, (struct sockaddr *) &addr, &len) };
    if (clientsd < 0)
    {
      report = "Unable to accept client";
      continue;
    }

    std::cout << "Received client\n";
    cb(clientsd);
    close(clientsd);
    std::cout << "Client closed\n";
  }

  std::cerr << report << '\n';
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

bool HttpsServer::run(const std::function<void(const int)> &cb)
{
  while (1)
  {
    struct sockaddr_in addr;
    uint len { sizeof addr };
    int clientsd { accept(sd, (struct sockaddr *) &addr, &len) };
    if (clientsd < 0)
    {
      report = "Unable to accept client";
      continue;
    }

    SecureClientPair client;
    if (!client.configure_context(report))
    {
      std::cerr << "Configure client context: " << report << std::endl;
      close(clientsd);
      return false;
    }

    std::string document { "void" };
	  client.set_tlsext_hostname(hostname);
    sslserver.set_fd(clientsd);
    sslserver.set_CTX(client);
    ssize_t err;
    if ((err = sslserver.accept()) < 1)
      report = "[SSL] SSL_accept(): " + std::to_string(sslserver.get_error(err));
    else
      sslserver.write(document);

    sslserver.clear();
    close(clientsd);
  }

  return true;
}
