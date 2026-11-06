#include <unity.h>

#include <set>
#include <string>

#include "../../src/vpn_storage.h"

class FakePreferences {
 public:
  bool isKey(const char* key) const { return keys.count(key) != 0; }
  bool remove(const char* key) {
    if (key == failedKey) return false;
    return keys.erase(key) != 0;
  }

  std::set<std::string> keys;
  std::string failedKey;
};

void testRemovesMarkerAndAllWireGuardKeys() {
  FakePreferences prefs;
  prefs.keys = {"wg_ok", "wg_priv", "wg_addr", "wg_bits", "wg_pub", "wg_psk",
                "wg_host", "wg_port", "wg_al", "wg_ka"};

  TEST_ASSERT_EQUAL(static_cast<int>(vpn_storage::RemoveResult::Success),
                    static_cast<int>(vpn_storage::removeConfig(prefs)));
  TEST_ASSERT_TRUE(prefs.keys.empty());
}

void testDoesNotReportSuccessWhenMarkerCannotBeRemoved() {
  FakePreferences prefs;
  prefs.keys = {"wg_ok", "wg_priv"};
  prefs.failedKey = "wg_ok";

  TEST_ASSERT_EQUAL(static_cast<int>(vpn_storage::RemoveResult::MarkerFailed),
                    static_cast<int>(vpn_storage::removeConfig(prefs)));
  TEST_ASSERT_TRUE(prefs.isKey("wg_priv"));
}

void testReportsUnremovedDataAndContinuesCleanup() {
  FakePreferences prefs;
  prefs.keys = {"wg_ok", "wg_priv", "wg_addr", "wg_pub", "wg_psk"};
  prefs.failedKey = "wg_addr";

  TEST_ASSERT_EQUAL(static_cast<int>(vpn_storage::RemoveResult::DataFailed),
                    static_cast<int>(vpn_storage::removeConfig(prefs)));
  TEST_ASSERT_FALSE(prefs.isKey("wg_ok"));
  TEST_ASSERT_FALSE(prefs.isKey("wg_priv"));
  TEST_ASSERT_TRUE(prefs.isKey("wg_addr"));
  TEST_ASSERT_FALSE(prefs.isKey("wg_pub"));
}

int main() {
  UNITY_BEGIN();
  RUN_TEST(testRemovesMarkerAndAllWireGuardKeys);
  RUN_TEST(testDoesNotReportSuccessWhenMarkerCannotBeRemoved);
  RUN_TEST(testReportsUnremovedDataAndContinuesCleanup);
  return UNITY_END();
}
