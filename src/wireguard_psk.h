#pragma once

#include <Arduino.h>
#include <WireGuard-ESP32.h>
#include <lwip/ip4_addr.h>
#include <lwip/netif.h>
extern "C" {
#include "wireguardif.h"
}
#include "wg_routes.h"

class WireGuardPsk {
 public:
  bool begin(const IPAddress& localIP, const char* privateKey, const char* remotePeerAddress,
             const char* remotePeerPublicKey, uint16_t remotePeerPort, const uint8_t* presharedKey,
             size_t tunnelIndex, const wg_routes::Route* routes, size_t routeCount);
  void end();
  bool is_initialized() const { return initialized_; }
  static struct netif* routeForDestination(const ip4_addr_t* destination);

 private:
  static const size_t MAX_ROUTES = 8;
  static const size_t MAX_INSTANCES = 3;
  static WireGuardPsk* instances_[MAX_INSTANCES];
  bool initialized_ = false;
  struct netif netifStorage_ = {};
  struct netif* netif_ = nullptr;
  uint8_t peerIndex_ = WIREGUARDIF_INVALID_INDEX;
  wg_routes::Route routes_[MAX_ROUTES] = {};
  size_t routeCount_ = 0;
};
