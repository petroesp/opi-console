#pragma once

namespace vpn_storage {

enum class RemoveResult { Success, MarkerFailed, DataFailed };

template <typename Preferences>
RemoveResult removeConfig(Preferences& preferences) {
  if (preferences.isKey("wg_ok")) {
    preferences.remove("wg_ok");
    if (preferences.isKey("wg_ok")) return RemoveResult::MarkerFailed;
  }

  bool removed = true;
  const char* keys[] = {"wg_priv", "wg_addr", "wg_bits", "wg_pub", "wg_psk",
                        "wg_host", "wg_port", "wg_al", "wg_ka"};
  for (const char* key : keys) {
    if (!preferences.isKey(key)) continue;
    preferences.remove(key);
    if (preferences.isKey(key)) removed = false;
  }
  return removed ? RemoveResult::Success : RemoveResult::DataFailed;
}

}  // namespace vpn_storage
