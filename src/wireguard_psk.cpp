#include "wireguard_psk.h"

#include <lwip/netdb.h>
#include <lwip/ip.h>
#include <string.h>

extern "C" {
#include "wireguard-platform.h"
#include "wireguardif.h"
}

WireGuardPsk* WireGuardPsk::instances_[WireGuardPsk::MAX_INSTANCES] = {};

bool WireGuardPsk::begin(const IPAddress& localIP, const char* privateKey,
                         const char* remotePeerAddress, const char* remotePeerPublicKey,
                         uint16_t remotePeerPort, const uint8_t* presharedKey,
                         size_t tunnelIndex, const wg_routes::Route* routes, size_t routeCount) {
  if (initialized_ || !privateKey || !remotePeerAddress || !remotePeerPublicKey ||
      remotePeerPort == 0 || tunnelIndex >= MAX_INSTANCES || !routes || routeCount == 0 ||
      routeCount > MAX_ROUTES || instances_[tunnelIndex]) return false;

  for (size_t i = 0; i < MAX_INSTANCES; ++i)
    if (instances_[i] == this) return false;

  ip_addr_t endpointIP = IPADDR4_INIT_BYTES(0, 0, 0, 0);
  bool endpointResolved = false;
  for (int retry = 0; retry < 5; ++retry) {
    struct addrinfo* result = nullptr;
    struct addrinfo hints = {};
    if (lwip_getaddrinfo(remotePeerAddress, nullptr, &hints, &result) != 0) {
      vTaskDelay(pdMS_TO_TICKS(2000));
      continue;
    }

    if (result && result->ai_family == AF_INET) {
      const struct in_addr address = reinterpret_cast<struct sockaddr_in*>(result->ai_addr)->sin_addr;
      inet_addr_to_ip4addr(ip_2_ip4(&endpointIP), &address);
      endpointResolved = true;
    }
    lwip_freeaddrinfo(result);
    if (endpointResolved) break;
    return false;
  }
  if (!endpointResolved) return false;

  struct wireguardif_init_data initData = {};
  initData.private_key = privateKey;
  initData.listen_port = 0;
  initData.bind_netif = nullptr;

  ip_addr_t localAddress = IPADDR4_INIT(static_cast<uint32_t>(localIP));
  ip_addr_t netmask = IPADDR4_INIT_BYTES(255, 255, 255, 255);
  ip_addr_t gateway = IPADDR4_INIT_BYTES(0, 0, 0, 0);
  netif_ = netif_add(&netifStorage_, ip_2_ip4(&localAddress), ip_2_ip4(&netmask),
                     ip_2_ip4(&gateway), &initData, &wireguardif_init, &ip_input);
  if (!netif_) return false;

  netif_set_up(netif_);
  wireguard_platform_init();

  struct wireguardif_peer peer = {};
  wireguardif_peer_init(&peer);
  peer.endpoint_ip = endpointIP;
  peer.public_key = remotePeerPublicKey;
  peer.preshared_key = presharedKey;
  peer.allowed_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
  peer.allowed_mask = IPADDR4_INIT_BYTES(0, 0, 0, 0);
  peer.endport_port = remotePeerPort;

  const err_t addResult = wireguardif_add_peer(netif_, &peer, &peerIndex_);
  if (addResult != ERR_OK || peerIndex_ == WIREGUARDIF_INVALID_INDEX) {
    wireguardif_shutdown(netif_);
    netif_remove(netif_);
    netif_ = nullptr;
    return false;
  }

  memcpy(routes_, routes, routeCount * sizeof(routes_[0]));
  routeCount_ = routeCount;
  instances_[tunnelIndex] = this;
  wireguardif_connect(netif_, peerIndex_);
  initialized_ = true;
  return true;
}

void WireGuardPsk::end() {
  if (!initialized_) return;

  wireguardif_disconnect(netif_, peerIndex_);
  wireguardif_remove_peer(netif_, peerIndex_);
  peerIndex_ = WIREGUARDIF_INVALID_INDEX;
  wireguardif_shutdown(netif_);
  netif_remove(netif_);
  netif_ = nullptr;
  for (size_t i = 0; i < MAX_INSTANCES; ++i)
    if (instances_[i] == this) instances_[i] = nullptr;
  memset(routes_, 0, sizeof(routes_));
  routeCount_ = 0;
  initialized_ = false;
}

struct netif* WireGuardPsk::routeForDestination(const ip4_addr_t* destination) {
  const uint32_t address = (static_cast<uint32_t>(ip4_addr1(destination)) << 24) |
                           (static_cast<uint32_t>(ip4_addr2(destination)) << 16) |
                           (static_cast<uint32_t>(ip4_addr3(destination)) << 8) |
                           static_cast<uint32_t>(ip4_addr4(destination));
  struct netif* selected = nullptr;
  uint8_t bestPrefix = 0;
  for (size_t i = 0; i < MAX_INSTANCES; ++i) {
    WireGuardPsk* instance = instances_[i];
    if (!instance || !instance->initialized_) continue;
    for (size_t route = 0; route < instance->routeCount_; ++route) {
      const wg_routes::Route& candidate = instance->routes_[route];
      if (wg_routes::matches(candidate, address) &&
          (!selected || candidate.prefix > bestPrefix)) {
        selected = instance->netif_;
        bestPrefix = candidate.prefix;
      }
    }
  }
  return selected;
}
