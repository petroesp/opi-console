#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace wifi_profiles {

static const size_t MAX_PROFILES = 5;
static const size_t SSID_CAPACITY = 33;
static const size_t PASSWORD_CAPACITY = 64;
static const uint8_t STORE_VERSION = 1;

struct Profile {
  char ssid[SSID_CAPACITY];
  char password[PASSWORD_CAPACITY];
};

struct Store {
  uint8_t version;
  uint8_t count;
  Profile profiles[MAX_PROFILES];
};

inline bool valid(const Profile& profile) {
  const char* ssidEnd = static_cast<const char*>(memchr(profile.ssid, '\0', sizeof(profile.ssid)));
  const char* passwordEnd =
      static_cast<const char*>(memchr(profile.password, '\0', sizeof(profile.password)));
  return ssidEnd && passwordEnd && ssidEnd != profile.ssid &&
         static_cast<size_t>(ssidEnd - profile.ssid) <= 32 &&
         static_cast<size_t>(passwordEnd - profile.password) <= 63;
}

inline bool valid(const Store& store) {
  if (store.version != STORE_VERSION || store.count == 0 || store.count > MAX_PROFILES) return false;
  for (size_t i = 0; i < store.count; ++i)
    if (!valid(store.profiles[i])) return false;
  return true;
}

inline bool inheritPassword(const Profile* profiles, size_t count, Profile& target) {
  for (size_t i = 0; i < count; ++i) {
    if (strcmp(profiles[i].ssid, target.ssid) == 0) {
      memcpy(target.password, profiles[i].password, sizeof(target.password));
      return true;
    }
  }
  return false;
}

inline size_t nextIndex(size_t current, size_t count) {
  return count == 0 || current >= count ? 0 : (current + 1) % count;
}

}  // namespace wifi_profiles
