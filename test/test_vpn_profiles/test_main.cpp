#include <unity.h>

#include <string.h>

#include "../../src/vpn_profiles.h"

void testAcceptsThreeValidTunnelProfiles() {
  vpn_profiles::Store store = {};
  store.version = vpn_profiles::VERSION;
  for (size_t i = 0; i < vpn_profiles::COUNT; ++i) {
    vpn_profiles::Config& config = store.configs[i];
    config.configured = 1;
    strcpy(config.priv, "private");
    strcpy(config.addr, "10.0.0.2");
    strcpy(config.pub, "public");
    strcpy(config.host, "vpn.example");
    strcpy(config.allowed, "10.1.0.0/16");
    config.port = 51820;
    config.bits = 32;
  }
  TEST_ASSERT_TRUE(vpn_profiles::validStore(store));
}

void testRejectsTruncatedConfigStringsAndWrongVersion() {
  vpn_profiles::Store store = {};
  store.version = vpn_profiles::VERSION;
  vpn_profiles::Config& config = store.configs[0];
  config.configured = 1;
  memset(config.priv, 'x', sizeof(config.priv));
  strcpy(config.addr, "10.0.0.2");
  strcpy(config.pub, "public");
  strcpy(config.host, "vpn.example");
  strcpy(config.allowed, "10.1.0.0/16");
  config.port = 51820;
  TEST_ASSERT_FALSE(vpn_profiles::validStore(store));

  memset(&config, 0, sizeof(config));
  store.version++;
  TEST_ASSERT_FALSE(vpn_profiles::validStore(store));
}

void testClearsOnlySelectedProfileAndChecksBounds() {
  vpn_profiles::Store store = {};
  store.version = vpn_profiles::VERSION;
  store.configs[0].configured = 1;
  store.configs[1].configured = 1;
  TEST_ASSERT_TRUE(vpn_profiles::clear(store, 1));
  TEST_ASSERT_EQUAL_UINT8(1, store.configs[0].configured);
  TEST_ASSERT_EQUAL_UINT8(0, store.configs[1].configured);
  TEST_ASSERT_FALSE(vpn_profiles::clear(store, vpn_profiles::COUNT));
}

int main() {
  UNITY_BEGIN();
  RUN_TEST(testAcceptsThreeValidTunnelProfiles);
  RUN_TEST(testRejectsTruncatedConfigStringsAndWrongVersion);
  RUN_TEST(testClearsOnlySelectedProfileAndChecksBounds);
  return UNITY_END();
}
