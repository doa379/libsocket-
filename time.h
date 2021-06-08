#pragma once
#include <chrono>

using time_p = std::chrono::time_point<std::chrono::system_clock>;

class Time
{
protected:
  unsigned timeout;
public:
  Time(unsigned timeout = 0) : timeout(timeout) { }
  time_p now(void) noexcept { return std::chrono::system_clock::now(); }
  template<typename T>
  std::size_t diffpt(time_p t1, time_p t0)
  {
    return std::chrono::duration_cast<T>(t1.time_since_epoch()).count() -
      std::chrono::duration_cast<T>(t0.time_since_epoch()).count();
  }
  void set_timeout(const unsigned timeout) { this->timeout = timeout; }
};
