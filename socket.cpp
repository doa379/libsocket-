#include <cstring>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <iostream>
#include <openssl/err.h>
#include "socket.h"

Http::Http(const float httpver)
{
  sprintf(this->httpver, "%.1f", httpver);
  memset(&sa, 0, sizeof sa);
  try {
    sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd < 0)
      throw "Socket creation failed";
  }
  catch(const std::string &ex)
  {
    report = ex;
    throw;
  }
}

Http::~Http(void)
{
  close(sd);
}

bool Http::init_connect(const std::string &hostname, const unsigned port)
{
  this->hostname = hostname;
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

Secure::Secure(void)
{
  //OpenSSL_add_ssl_algorithms();
  //SSL_load_error_strings();
}

Secure::~Secure(void)
{

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
  catch(const std::string &ex)
  {
    std::cerr << "Unable to create " + ex + '\n';
    throw;
  }
}

SecureClientPair::~SecureClientPair(void)
{
  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
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
  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
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
  if ((err = SSL_CTX_use_certificate_file(ctx, CERT.c_str(), SSL_FILETYPE_PEM)) < 1)
  {
    report = "[SSL] configure_context(): " + std::to_string(SSL_get_error(ssl, err));
    return false;
  }

  if ((err = SSL_CTX_use_PrivateKey_file(ctx, KEY.c_str(), SSL_FILETYPE_PEM)) < 1 )
  {
    report = "[SSL] configure_context(): " + std::to_string(SSL_get_error(ssl, err));
    return false;
  }

  return true;
}

Client::Client(const float httpver) : Http(httpver)
{

}

Client::~Client(void)
{

}

bool Client::connect(const std::string &hostname, const unsigned port)
{
  if (!init_connect(hostname, port))
    return false;
  return connector();
}

void Client::recvreq(void)
{
  char p;
  bool res;
  do
  {
    res = reader(&p);
    response_header += p;
  }
  while (res && response_header.find("\r\n\r\n") == std::string::npos);

  std::size_t content_length { 0 };
  if (std::regex_search(response_header, match, content_length_regex) &&
      (content_length = std::stol(response_header.substr(match.prefix().length() + 16))))
    do
    {
      res = reader(&p);
      response_body += p;
    }
    while (res && response_body.size() < content_length);

  else
  {
    while (reader(&p))
    {
      response_body += p;
      response_cb(response_body);
    }
  }
}

bool Client::sendreq(REQUEST req, const std::string &endpoint, const std::vector<std::string> &HEADERS, const std::string &data)
{
  std::string req_type { 
    req == GET ? "GET" : 
    req == POST ? "POST" : 
    req == PUT ? "PUT" : 
    req == DELETE ? "DELETE" : 
    "" };

  if (!req_type.size())
  {
    report = "Unknown request type";
    return false;
  }

  std::string request { 
    req_type + " " + endpoint + " " + "HTTP/" + std::string(httpver) + "\r\n" +
    "Host: " + hostname + "\r\n" +
    "User-Agent: " + agent + "\r\n" +
    "Accept: */*" + "\r\n" };

  for (auto &h : HEADERS)
    request += h + "\r\n";

  if (data.size())
    request += "Content-Length: " + std::to_string(data.size()) + "\r\n\r\n" + data;

  request += "\r\n";
  return writer(request);
}

HttpClient::HttpClient(const float httpver) : Client(httpver)
{
  connector = [this](void) -> bool { 
    if (::connect(sd, (struct sockaddr *) &sa, sizeof sa) < 0)
    {
      report = "Connect error";
      return false;
    }
    return true;
  };
  reader = [this](char *p) -> bool {
    if (::recv(sd, p, sizeof *p, 0) < 1)
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

HttpsClient::HttpsClient(const float httpver) : Client(httpver)
{
  OpenSSL_add_ssl_algorithms();
  SSL_load_error_strings();
  connector = [this](void) -> bool {
    if (::connect(sd, (struct sockaddr *) &sa, sizeof sa) < 0)
    {
      report = "Connect error";
      return false;
    }
    configure_context(report);
    SSL_set_tlsext_host_name(ssl, hostname.c_str());
    SSL_set_fd(ssl, sd);
    ssize_t err;
    if ((err = SSL_connect(ssl)) < 0)
    {
      err = SSL_get_error(ssl, err);
      report = "[SSL] Connect: " + std::to_string(SSL_get_error(ssl, err));
      return false;
    }
    return true;
  };
  reader = [this](char *p) -> bool {
    ssize_t err { SSL_read(ssl, p, sizeof *p) };
    if (err < 1)
    {
      report = "Read: " + std::to_string(SSL_get_error(ssl, err));
      return false;
    }
    return true;
  };
  writer = [this](const std::string &request) -> bool {
    if (SSL_write(ssl, request.c_str(), request.size()) < 0)
    {
      report = "Write: " + std::string(ERR_error_string(ERR_get_error(), 0));
      return false;
    }
    return true;
  };
}

HttpsClient::~HttpsClient(void)
{

}

Server::Server(const float httpver) : Http(httpver)
{

}

bool Server::connect(const std::string &hostname, const unsigned port)
{
  if (!init_connect(hostname, port))
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

HttpServer::HttpServer(void) : Server(DEFAULT_HTTPVER)
{

}

HttpServer::~HttpServer(void)
{

}

bool HttpServer::run(const std::string &document)
{
  is_running = true;
  while(is_running)
  {
    struct sockaddr_in addr;
    uint len { sizeof addr };
    int clientsd { accept(sd, (struct sockaddr *) &addr, &len) };
    if (clientsd < 0)
    {
      report = "Unable to accept client";
      return false;
    }
    if (::write(clientsd, document.c_str(), document.size()) < 0)
    {
      report = "Error writing";
      return false;
    }
    close(clientsd);
  }

  return true;
}

HttpsServer::HttpsServer(void) : Server(DEFAULT_HTTPVER)
{
  OpenSSL_add_ssl_algorithms();
  SSL_load_error_strings();
}

HttpsServer::~HttpsServer(void)
{

}

int HttpsServer::sni_cb(SSL *ssl, int *ad, void *arg)
{
  /*
    UNUSED(ad);
    UNUSED(arg);

    ASSERT(ssl);
    if (ssl == NULL)
        return SSL_TLSEXT_ERR_NOACK;
  */
  HttpsServer *svr { (HttpsServer *) arg };
    const char* servername = SSL_get_servername(svr->ssl, TLSEXT_NAMETYPE_host_name);
    (void) servername;
    /*
    ASSERT(servername && servername[0]);
    if (!servername || servername[0] == '\0')
        return SSL_TLSEXT_ERR_NOACK;
    */
    /* Does the default cert already handle this domain?
    if (IsDomainInDefCert(servername))
        return SSL_TLSEXT_ERR_OK;
    */
    /* Need a new certificate for this domain */
    //SSL_CTX* ctx = GetServerContext(servername);
    /*
    ASSERT(ctx != NULL);
    if (ctx == NULL)
        return SSL_TLSEXT_ERR_NOACK;   
    */
    /* Useless return value */
    SSL_CTX *v = SSL_set_SSL_CTX(svr->ssl, svr->client.ctx);
    (void) v;
/*
    ASSERT(v == ctx);
    if (v != ctx)   
        return SSL_TLSEXT_ERR_NOACK;
*/
    return SSL_TLSEXT_ERR_OK;
}

bool HttpsServer::run(const std::string &document)
{
  if (!client.configure_context(report) ||
      !configure_context(report))
  {
    std::cerr << "Configure context(s) " << report << std::endl;
    return false;
  }
  
  is_running = true;
  while (is_running)
  {
    struct sockaddr_in addr;
    uint len { sizeof addr };
    int clientsd { accept(sd, (struct sockaddr *) &addr, &len) };
    if (clientsd < 0)
    {
      report = "Unable to accept client";
      return false;
    }

	  SSL_set_tlsext_host_name(client.ssl, hostname.c_str());
		//SSL_CTX_set_tlsext_servername_callback(ctx, sni_cb);
    //SSL_CTX_set_tlsext_servername_arg(ctx, this);
    SSL_set_fd(ssl, clientsd);
    SSL_set_SSL_CTX(ssl, client.ctx);
    SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    ssize_t err;
    if ((err = SSL_accept(ssl)) < 1)
      report = "[SSL] SSL_accept(): " + std::to_string(SSL_get_error(ssl, err));
    else
      SSL_write(ssl, document.c_str(), document.size());

    close(clientsd);
  }

  return true;
}
