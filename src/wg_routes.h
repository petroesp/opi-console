#pragma once

#include <stddef.h>
#include <stdint.h>

namespace wg_routes {

struct Route {
  uint32_t network;
  uint32_t mask;
  uint8_t prefix;
};

inline bool parseIpv4Cidr(const char* text, Route& route) {
  if (!text || !*text) return false;
  uint32_t address = 0;
  const char* cursor = text;
  for (int octet = 0; octet < 4; ++octet) {
    if (*cursor < '0' || *cursor > '9') return false;
    unsigned value = 0;
    unsigned digits = 0;
    while (*cursor >= '0' && *cursor <= '9') {
      value = value * 10 + static_cast<unsigned>(*cursor - '0');
      if (++digits > 3 || value > 255) return false;
      ++cursor;
    }
    address = (address << 8) | value;
    if (octet < 3) {
      if (*cursor++ != '.') return false;
    }
  }

  unsigned prefix = 32;
  if (*cursor == '/') {
    ++cursor;
    if (*cursor < '0' || *cursor > '9') return false;
    prefix = 0;
    unsigned digits = 0;
    while (*cursor >= '0' && *cursor <= '9') {
      prefix = prefix * 10 + static_cast<unsigned>(*cursor - '0');
      if (++digits > 2 || prefix > 32) return false;
      ++cursor;
    }
  }
  if (*cursor != '\0') return false;

  route.prefix = static_cast<uint8_t>(prefix);
  route.mask = prefix == 0 ? 0 : (0xFFFFFFFFu << (32 - prefix));
  route.network = address & route.mask;
  return true;
}

inline bool matches(const Route& route, uint32_t address) {
  return (address & route.mask) == route.network;
}

inline int bestMatch(const Route* routes, const size_t* owners, size_t count,
                     uint32_t address) {
  int best = -1;
  uint8_t bestPrefix = 0;
  for (size_t i = 0; i < count; ++i) {
    if (!matches(routes[i], address)) continue;
    if (best < 0 || routes[i].prefix > bestPrefix) {
      best = static_cast<int>(owners[i]);
      bestPrefix = routes[i].prefix;
    }
  }
  return best;
}

inline bool overlaps(const Route& a, const Route& b) {
  const uint32_t commonMask = a.mask & b.mask;
  return (a.network & commonMask) == (b.network & commonMask);
}

inline bool same(const Route& a, const Route& b) {
  return a.prefix == b.prefix && a.network == b.network;
}

}  // namespace wg_routes
