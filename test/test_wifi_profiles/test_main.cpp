#include <unity.h>

#include <string.h>

#include "../../src/wifi_profiles.h"

void testValidatesProfileLengthsAndTermination() {
  wifi_profiles::Profile profile = {};
  strcpy(profile.ssid, "home");
  strcpy(profile.password, "secret");
  TEST_ASSERT_TRUE(wifi_profiles::valid(profile));

  memset(profile.ssid, 's', sizeof(profile.ssid));
  TEST_ASSERT_FALSE(wifi_profiles::valid(profile));
  strcpy(profile.ssid, "home");
  memset(profile.password, 'p', sizeof(profile.password));
  TEST_ASSERT_FALSE(wifi_profiles::valid(profile));
}

void testValidatesProfileStoreBoundsAndEntries() {
  wifi_profiles::Store store = {};
  store.version = wifi_profiles::STORE_VERSION;
  store.count = 1;
  strcpy(store.profiles[0].ssid, "home");
  TEST_ASSERT_TRUE(wifi_profiles::valid(store));

  store.count = wifi_profiles::MAX_PROFILES + 1;
  TEST_ASSERT_FALSE(wifi_profiles::valid(store));
  store.count = 1;
  store.version++;
  TEST_ASSERT_FALSE(wifi_profiles::valid(store));
}

void testAcceptsMaximumLengthsAndOpenNetwork() {
  wifi_profiles::Profile profile = {};
  memset(profile.ssid, 's', 32);
  profile.ssid[32] = '\0';
  memset(profile.password, 'p', 63);
  profile.password[63] = '\0';
  TEST_ASSERT_TRUE(wifi_profiles::valid(profile));

  profile.password[0] = '\0';
  TEST_ASSERT_TRUE(wifi_profiles::valid(profile));
}

void testInheritsPasswordOnlyForMatchingNetwork() {
  wifi_profiles::Profile saved[2] = {};
  strcpy(saved[0].ssid, "home");
  strcpy(saved[0].password, "secret");
  strcpy(saved[1].ssid, "guest");
  strcpy(saved[1].password, "guest-pass");
  wifi_profiles::Profile target = {};
  strcpy(target.ssid, "guest");

  TEST_ASSERT_TRUE(wifi_profiles::inheritPassword(saved, 2, target));
  TEST_ASSERT_EQUAL_STRING("guest-pass", target.password);

  strcpy(target.ssid, "new-network");
  memset(target.password, 0, sizeof(target.password));
  TEST_ASSERT_FALSE(wifi_profiles::inheritPassword(saved, 2, target));
  TEST_ASSERT_EQUAL_CHAR('\0', target.password[0]);
}

void testCyclesProfileIndices() {
  TEST_ASSERT_EQUAL_UINT32(1, wifi_profiles::nextIndex(0, 5));
  TEST_ASSERT_EQUAL_UINT32(0, wifi_profiles::nextIndex(4, 5));
  TEST_ASSERT_EQUAL_UINT32(0, wifi_profiles::nextIndex(9, 5));
  TEST_ASSERT_EQUAL_UINT32(0, wifi_profiles::nextIndex(1, 0));
}

int main() {
  UNITY_BEGIN();
  RUN_TEST(testValidatesProfileLengthsAndTermination);
  RUN_TEST(testValidatesProfileStoreBoundsAndEntries);
  RUN_TEST(testAcceptsMaximumLengthsAndOpenNetwork);
  RUN_TEST(testInheritsPasswordOnlyForMatchingNetwork);
  RUN_TEST(testCyclesProfileIndices);
  return UNITY_END();
}
