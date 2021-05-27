#include <random>
#include <sstream>

int rand(std::size_t a, std::size_t b)
{
  std::random_device dev;
  std::mt19937 rng(dev());
  std::uniform_int_distribution<std::mt19937::result_type> dist(a, b);
  return dist(rng);
}

std::string to_base16(std::size_t arg)
{
  std::stringstream stream;
  stream << std::hex << arg;
  return "0x" + stream.str();
}
