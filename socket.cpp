#include <cstring>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include "socket.h"

Http::Http(const float httpver)
{
  sprintf(this->httpver, "%.1f", httpver);
  sd = socket(AF_INET, SOCK_STREAM, 0);
  memset(&sa, 0, sizeof sa);
  sa.sin_family = AF_INET;
}

Http::~Http(void)
{
  close(sd);
}

bool Http::init_connect(const std::string &hostname, const unsigned port)
{
  this->hostname = hostname;
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

HttpClient::HttpClient(const float httpver) : Http(httpver)
{

}

HttpClient::~HttpClient(void)
{

}

bool HttpClient::connect(const std::string &hostname, const unsigned port)
{
  if (!init_connect(hostname, port))
    return false;
  if (::connect(sd, (struct sockaddr *) &sa,	sizeof sa) < 0)
  {
    report = "Connect error";
    return false;
  }

  return true;
}

bool HttpClient::recvreq(void)
{
  char p;
  ssize_t err;
  bool body { 0 };
  response_header.clear();
  response_body.clear();
  while ((err = ::recv(sd, &p, sizeof p, 0)))
  {
    if (err < 0)
    {
      report = "Read error";
      return false;
    }
    
    if (!body)
    {
      response_header += p;
      if (response_header.find("\r\n\r\n") < std::string::npos)
        body = 1;
    }

    else
      response_body += p;
  }
  
  return true;
}

bool HttpClient::sendreq(REQUEST req, const std::string &endpoint, const std::vector<std::string> &HEADERS, const std::string &data)
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
  ssize_t err { ::write(sd, request.c_str(), request.size()) };
  if (err < 0)
  {
    report = "Write error";
    return false;
  }
  
  return true;
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

bool HttpServer::run(void)
{
  while(1)
  {
    struct sockaddr_in addr;
    uint len = sizeof addr;
i    const char reply[] = "Server\n";
    int clientfd = accept(sd, (struct sockaddr *) &addr, &len);
    if (clientfd < 0)
    {
      report = "Unable to accept";
      return false;
    }

    if (::write(clientfd, reply, strlen(reply)) < 0)
    {
      report = "Error writing";
      return false;
    }
    close(clientfd);
  }

  return true;
}
