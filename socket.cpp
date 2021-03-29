#include <cstring>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include "socket.h"

ClientSocket::ClientSocket(const float http_ver)
{
  sprintf(this->http_ver, "%.1f", http_ver);
  sd = socket(AF_INET, SOCK_STREAM, 0);
  memset(&sa, 0, sizeof sa);
  sa.sin_family = AF_INET;
}

ClientSocket::~ClientSocket(void)
{
  close(sd);
}

bool ClientSocket::connect(const std::string &hostname, const unsigned port)
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
  int err { ::connect(sd, (struct sockaddr *) &sa,	sizeof sa) };
  if (err == -1)
  {
    report = "Connect error";
    return false;
  }

  return true;
}

bool ClientSocket::recvreq(char *buffer, size_t size)
{
  ssize_t err { ::recv(sd, buffer, size, 0) };
  if (err < 0)
  {
    report = "Read error";
    return false;
  }

  return true;
}

bool ClientSocket::sendreq(REQUEST req, const std::string &endpoint, const std::vector<std::string> &HEADERS, const std::string &data)
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
    req_type + " " + endpoint + " " + "HTTP/" + std::string(http_ver) + "\r\n" +
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

std::string &ClientSocket::get_report(void)
{
  return report;
}
