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

bool Client::recvreq(void)
{
  char p;
  bool body { 0 }, err;
  response_header.clear();
  response_body.clear();
  while ((err = reader(&p)))
  {
    if (!body)
    {
      response_header += p;
      if (response_header.find("\r\n\r\n") < std::string::npos)
        body = 1;
    }

    else
      response_body += p;
  }
  
  return err;
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

HttpServer::HttpServer(void) : Http(DEFAULT_HTTPVER)
{

}

HttpServer::~HttpServer(void)
{

}

bool HttpServer::connect(const std::string &hostname, const unsigned port)
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

bool HttpServer::run(const std::string &document)
{
  is_running = 1;
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

Secure::Secure(void)
{
  OpenSSL_add_ssl_algorithms();
  SSL_load_error_strings();
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

Secure::~Secure(void)
{
  SSL_free(ssl);
  SSL_CTX_free(ctx);
}

HttpsClient::HttpsClient(const float httpver) : Client(httpver), Secure()
{
  connector = [this](void) -> bool {
    if (::connect(sd, (struct sockaddr *) &sa, sizeof sa) < 0)
    {
      report = "Connect error";
      return false;
    }
    SSL_set_tlsext_host_name(ssl, hostname.c_str());
    SSL_set_fd(ssl, sd);
    if (SSL_connect(ssl) < 0)
    {
      report = "[SSL] Connect: " + 
        std::string(ERR_error_string(ERR_get_error(), 0));
      return false;
      }
    std::cout << "Connected " << hostname << std::endl;
    return true;
  };
  reader = [this](char *p) -> bool {
    if (SSL_read(ssl, p, sizeof *p) == -1)
    {
      report = "Read: " + 
        std::string(ERR_error_string(ERR_get_error(), err));
      return false;
    }
    return true;
  };
  writer = [this](const std::string &request) -> bool {
    if (SSL_write(ssl, request.c_str(), request.size()) < 0)
    {
      report = "Write: " + 
        std::string(ERR_error_string(ERR_get_error(), err));
      return false;
    }
    return true;
  };
}

HttpsClient::~HttpsClient(void)
{

}
