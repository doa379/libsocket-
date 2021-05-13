#pragma once
#include <chrono>

static const unsigned DEFAULT_TIMEOUT { 30 * 1000 };

using time_p = std::chrono::time_point<std::chrono::system_clock>;

template<typename T>
class Time
{
protected:
  unsigned timeout { DEFAULT_TIMEOUT };
public:
  time_p now(void) noexcept { return std::chrono::system_clock::now(); };
  std::size_t difftime(time_p t1, time_p t0)
  {
    return std::chrono::duration_cast<T>(t1.time_since_epoch()).count() -
      std::chrono::duration_cast<T>(t0.time_since_epoch()).count();
  }
  void set_timeout(const unsigned timeout) { this->timeout = timeout; };
};

