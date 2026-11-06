#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace vpn_profiles {

static const size_t COUNT = 3;
static const uint8_t VERSION = 1;

struct Config {
  uint8_t configured;
  char priv[45], addr[16], pub[45], psk[45], host[64], allowed[256];
  uint8_t bits;
  uint16_t port, keepalive;
};

struct Store {
  uint8_t version;
  Config configs[COUNT];
};

inline bool validConfig(const Config& config) {
  if (!config.configured) return true;
  return config.configured == 1 &&
         memchr(config.priv, '\0', sizeof(config.priv)) &&
         memchr(config.addr, '\0', sizeof(config.addr)) &&
         memchr(config.pub, '\0', sizeof(config.pub)) &&
         memchr(config.psk, '\0', sizeof(config.psk)) &&
         memchr(config.host, '\0', sizeof(config.host)) &&
         memchr(config.allowed, '\0', sizeof(config.allowed)) &&
         config.priv[0] && config.addr[0] && config.pub[0] &&
         config.host[0] && config.allowed[0] && config.port;
}

inline bool validStore(const Store& store) {
  if (store.version != VERSION) return false;
  for (size_t i = 0; i < COUNT; ++i)
    if (!validConfig(store.configs[i])) return false;
  return true;
}

inline bool clear(Store& store, size_t index) {
  if (index >= COUNT) return false;
  memset(&store.configs[index], 0, sizeof(store.configs[index]));
  return true;
}

}  // namespace vpn_profiles
