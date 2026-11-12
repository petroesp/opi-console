// OPi UART console gateway: ESP32-C3 + WiFi/AP + WireGuard + web console
#include <Arduino.h>
#include <WiFi.h>
#include <ESPmDNS.h>
#include <Preferences.h>
#include <LittleFS.h>
#include <ESPAsyncWebServer.h>
#include <U8g2lib.h>
#include <WireGuard-ESP32.h>
#include <mbedtls/md.h>
#include <mbedtls/base64.h>
#include <WiFiUdp.h>
#include <time.h>
#include <lwip/ip4.h>
#include "config.h"
#include "web_ui.h"
#include "ws_uart.h"
#include "uart_rx_buffer.h"
#include "wifi_profiles.h"
#include "vpn_storage.h"
#include "vpn_profiles.h"
#include "wireguard_psk.h"

extern "C" struct netif* __real_ip4_route_src(const ip4_addr_t* source, const ip4_addr_t* destination);
// lwIP is precompiled, so wrap its source-route selector to apply WireGuard
// AllowedIPs without changing the framework library. Prefer a matching live
// non-WireGuard interface; otherwise select the most specific configured route.
extern "C" struct netif* __wrap_ip4_route_src(const ip4_addr_t* source, const ip4_addr_t* destination) {
  for (struct netif* interface = netif_list; interface; interface = interface->next) {
    if (interface->name[0] == 'w' && interface->name[1] == 'g') continue;
    if (netif_is_up(interface) &&
        ip4_addr_netcmp(destination, netif_ip4_addr(interface), netif_ip4_netmask(interface)))
      return __real_ip4_route_src(source, destination);
  }
  struct netif* tunnel = WireGuardPsk::routeForDestination(destination);
  return tunnel ? tunnel : __real_ip4_route_src(source, destination);
}

enum { R_RO = 0, R_RW = 1, R_ADMIN = 2 };
static const char* ROLE_NAME[] = {"ro", "rw", "admin"};

static Preferences prefs;
static AsyncWebServer server(80);
static AsyncWebSocket ws0("/ws/0"), ws1("/ws/1");
static U8G2_SSD1306_128X32_UNIVISION_F_SW_I2C oled(U8G2_R0, PIN_OLED_SCL, PIN_OLED_SDA, U8X8_PIN_NONE);
static uint32_t restartAt = 0;

// ===================================================================== common helpers
// Escape JSON string content before constructing small JSON responses by hand.
static String jesc(const String& s) {
  String o; o.reserve(s.length() + 8);
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    if (c == '"' || c == '\\') { o += '\\'; o += c; }
    else if ((uint8_t)c < 32) o += ' ';
    else o += c;
  }
  return o;
}
static void sendJson(AsyncWebServerRequest* r, int code, const String& j) { r->send(code, "application/json", j); }
static void sendErr(AsyncWebServerRequest* r, int code, const String& m) { sendJson(r, code, "{\"error\":\"" + jesc(m) + "\"}"); }
static String P(AsyncWebServerRequest* r, const char* k) {
  const AsyncWebParameter* p = r->getParam(k, true);
  return p ? p->value() : String();
}

// ===================================================================== users and password storage
// User records are stored as a fixed-size NVS blob. Passwords are never stored
// directly: each record contains a random salt and an iterated SHA-256 digest.
struct User { char name[17]; uint8_t salt[16]; uint8_t hash[32]; uint8_t role; uint8_t used; uint8_t must; uint8_t pad; };
static User users[MAX_USERS];

// Derive a password digest with PW_ITER rounds. Rehashing the previous digest
// makes a database dump more expensive to brute-force than a single SHA-256.
static void hashPw(const char* pw, const uint8_t* salt, uint8_t* out) {
  uint8_t buf[32 + 16 + 64], h[32] = {0};
  size_t pl = strlen(pw); if (pl > 64) pl = 64;
  const mbedtls_md_info_t* mi = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  for (int i = 0; i < PW_ITER; i++) {
    size_t n = 0;
    if (i) { memcpy(buf, h, 32); n = 32; }
    memcpy(buf + n, salt, 16); n += 16;
    memcpy(buf + n, pw, pl); n += pl;
    mbedtls_md(mi, buf, n, h);
  }
  memcpy(out, h, 32);
}
// Compare all bytes even after finding a mismatch to avoid an early-exit timing leak.
static bool ctEq(const uint8_t* a, const uint8_t* b, size_t n) { uint8_t d = 0; for (size_t i = 0; i < n; i++) d |= a[i] ^ b[i]; return d == 0; }
static void setPw(User& u, const char* pw) { esp_fill_random(u.salt, 16); hashPw(pw, u.salt, u.hash); }
static bool checkPw(const User& u, const char* pw) { uint8_t h[32]; hashPw(pw, u.salt, h); return ctEq(h, u.hash, 32); }
static void saveUsers() { prefs.putBytes("users", users, sizeof(users)); }
static void loadUsers() {
  memset(users, 0, sizeof(users));
  if (prefs.getBytesLength("users") == sizeof(users)) { prefs.getBytes("users", users, sizeof(users)); return; }
  // First boot (or missing user database): create a temporary admin that must
  // change its password before any normal authenticated operation is allowed.
  strcpy(users[0].name, "admin"); users[0].role = R_ADMIN; users[0].used = 1; users[0].must = 1;
  setPw(users[0], "admin"); saveUsers();
}
static int findUser(const String& n) { for (int i = 0; i < MAX_USERS; i++) if (users[i].used && n == users[i].name) return i; return -1; }
static int countAdmins() { int c = 0; for (auto& u : users) if (u.used && u.role == R_ADMIN) c++; return c; }
static int roleFrom(const String& s) { for (int i = 0; i < 3; i++) if (s == ROLE_NAME[i]) return i; return -1; }
static bool validName(const String& n) {
  if (n.length() < 1 || n.length() > 16) return false;
  for (size_t i = 0; i < n.length(); i++) { char c = n[i]; if (!(isalnum(c) || c == '_' || c == '-' || c == '.')) return false; }
  return true;
}

// ===================================================================== sessions and authorization
// Session tokens live in RAM only; rebooting the ESP32 invalidates all logins.
struct Session { bool used; char tok[33]; int8_t user; uint32_t exp; };
static Session sess[MAX_SESS];

static bool sessValid(int i) {
  return i >= 0 && i < MAX_SESS && sess[i].used && (int32_t)(sess[i].exp - millis()) > 0 && users[sess[i].user].used;
}
static int findSessTok(const char* t) {
  for (int i = 0; i < MAX_SESS; i++) if (sess[i].used && !strcmp(sess[i].tok, t) && sessValid(i)) return i;
  return -1;
}
static int findSession(AsyncWebServerRequest* r) {
  if (!r->hasHeader("Cookie")) return -1;
  String c = r->header("Cookie");
  int p = c.indexOf("sid=");
  while (p > 0 && c[p - 1] != ' ' && c[p - 1] != ';') p = c.indexOf("sid=", p + 1);
  if (p < 0) return -1;
  String t = c.substring(p + 4, p + 36);
  return findSessTok(t.c_str());
}
static int newSession(int user, char* tokOut) {
  int slot = 0;
  for (int i = 0; i < MAX_SESS; i++) if (!sessValid(i)) { slot = i; break; }
  uint8_t rnd[16]; esp_fill_random(rnd, 16);
  for (int i = 0; i < 16; i++) sprintf(sess[slot].tok + i * 2, "%02x", rnd[i]);
  sess[slot].used = true; sess[slot].user = user; sess[slot].exp = millis() + SESSION_MS;
  strcpy(tokOut, sess[slot].tok);
  return slot;
}
static int sessionCount() { int n = 0; for (int i = 0; i < MAX_SESS; i++) if (sessValid(i)) n++; return n; }

// Enforce a minimum role and the first-login password change. On failure this
// helper sends the HTTP response itself and returns -1 to stop the route.
static int auth(AsyncWebServerRequest* r, int minRole, bool allowMust = false) {
  int si = findSession(r);
  if (si < 0) {
    Serial.printf("[AUTH] 401 %s cookie=%s\r\n", r->url().c_str(), r->hasHeader("Cookie") ? r->header("Cookie").c_str() : "NO");
    sendErr(r, 401, "auth"); return -1;
  }
  User& u = users[sess[si].user];
  if (u.must && !allowMust) { sendErr(r, 403, "must_change"); return -1; }
  if (u.role < minRole) { sendErr(r, 403, "Недостаточно прав"); return -1; }
  return si;
}

// Keep a small fixed table of login failures; this avoids heap allocation on
// each request while applying a temporary lockout per remote IP.
struct Fail { uint32_t ip; uint8_t n; uint32_t until; };
static Fail fails[8];
static Fail* failFor(uint32_t ip) {
  Fail* free_ = &fails[0];
  for (auto& f : fails) { if (f.ip == ip) return &f; if (f.ip == 0 || f.n == 0) free_ = &f; }
  free_->ip = ip; free_->n = 0; free_->until = 0; return free_;
}

// ===================================================================== UART terminals
// Each Console owns one hardware UART, its WebSocket, a bounded line history,
// a transmit-to-browser staging buffer, and a sequence-numbered RX ring buffer.
struct WsCli { bool used; uint32_t id; char tok[33]; int8_t user; };
struct Console {
  HardwareSerial* ser; AsyncWebSocket* ws;
  char lines[HIST_LINES][LINE_MAX]; uint16_t llen[HIST_LINES]; uint8_t head, cnt;
  char cur[LINE_MAX]; uint16_t clen;
  uint8_t out[OUT_MAX]; uint16_t olen; uint32_t lastFlush;
  uart_rx::Buffer<UART_RX_BUF> rx;
  WsCli cli[16];
};
static Console con[2];
static SemaphoreHandle_t mux;
static uint32_t lastUartActivity = 0;
// -1 means no UART is currently selected for the automatic OLED terminal view.
static int8_t activeUartScreen = -1;
static char terminalNames[2][25] = {"Pi #1", "Pi #2"};
#define LOCK()   xSemaphoreTakeRecursive(mux, portMAX_DELAY)
#define UNLOCK() xSemaphoreGiveRecursive(mux)

static void loadTerminalNames() {
  char stored[sizeof(terminalNames)] = {};
  if (prefs.getBytesLength("termNames") != sizeof(stored) ||
      prefs.getBytes("termNames", stored, sizeof(stored)) != sizeof(stored)) return;
  for (int i = 0; i < 2; ++i) {
    char* name = stored + i * sizeof(terminalNames[i]);
    if (!memchr(name, '\0', sizeof(terminalNames[i])) || name[0] == '\0') return;
  }
  memcpy(terminalNames, stored, sizeof(terminalNames));
}

// Persist framing parameters per port. parity is encoded as 0=none, 1=even,
// 2=odd so the settings blob remains compact and easy to validate on startup.
struct UartSettings { uint32_t baud; uint8_t bits; uint8_t parity; uint8_t stop; };
static const UartSettings DEFAULT_UART_SETTINGS = {UART_BAUD, 8, 0, 1};
static UartSettings uartSettings[2] = {DEFAULT_UART_SETTINGS, DEFAULT_UART_SETTINGS};

struct VoltageChannel {
  uint32_t sumMilliVolts;
  uint16_t averageMilliVolts;
  uint8_t samples;
  bool ready;
};
static VoltageChannel voltageChannels[3] = {};
static uint32_t voltageLastSampleAt = 0;

static bool validUartSettings(const UartSettings& s) {
  // Keep the ranges aligned with the web form and protect the configuration
  // lookup table in uartConfig() from out-of-range values read from NVS.
  return s.baud >= 300 && s.baud <= 2000000 && s.bits >= 5 && s.bits <= 8 &&
         s.parity <= 2 && (s.stop == 1 || s.stop == 2);
}
static uint32_t uartConfig(const UartSettings& s) {
  static const uint32_t configs[4][3][2] = {
    {{SERIAL_5N1, SERIAL_5N2}, {SERIAL_5E1, SERIAL_5E2}, {SERIAL_5O1, SERIAL_5O2}},
    {{SERIAL_6N1, SERIAL_6N2}, {SERIAL_6E1, SERIAL_6E2}, {SERIAL_6O1, SERIAL_6O2}},
    {{SERIAL_7N1, SERIAL_7N2}, {SERIAL_7E1, SERIAL_7E2}, {SERIAL_7O1, SERIAL_7O2}},
    {{SERIAL_8N1, SERIAL_8N2}, {SERIAL_8E1, SERIAL_8E2}, {SERIAL_8O1, SERIAL_8O2}}
  };
  return configs[s.bits - 5][s.parity][s.stop - 1];
}
// Ignore malformed or outdated NVS blobs and retain compile-time defaults.
static void loadUartSettings() {
  for (int i = 0; i < 2; ++i) {
    String key = String("uart") + i;
    size_t length = prefs.getBytesLength(key.c_str());
    if (!length) continue;
    UartSettings stored = {};
    if (length == sizeof(stored) && prefs.getBytes(key.c_str(), &stored, sizeof(stored)) == sizeof(stored) &&
        validUartSettings(stored)) {
      uartSettings[i] = stored;
    } else {
      Serial.printf("[UART] Invalid saved settings for Pi#%d; using defaults\r\n", i + 1);
      uartSettings[i] = DEFAULT_UART_SETTINGS;
    }
  }
}
// Configure both physical UARTs from the validated settings loaded at boot.
static void startUarts() {
  Serial0.setRxBufferSize(UART_RX_BUF);
  Serial0.begin(uartSettings[0].baud, uartConfig(uartSettings[0]), PIN_P1_RX, PIN_P1_TX);
  Serial1.setRxBufferSize(UART_RX_BUF);
  Serial1.begin(uartSettings[1].baud, uartConfig(uartSettings[1]), PIN_P2_RX, PIN_P2_TX);
}

static void voltageInit() {
  analogReadResolution(12);
  analogSetPinAttenuation(PIN_VOLTAGE1_ADC, ADC_11db);
  analogSetPinAttenuation(PIN_VOLTAGE2_ADC, ADC_11db);
  analogSetPinAttenuation(PIN_CURRENT_ADC, ADC_0db);
}

static void voltageTick() {
  const uint32_t now = millis();
  if ((uint32_t)(now - voltageLastSampleAt) < VOLTAGE_SAMPLE_INTERVAL_MS) return;
  voltageLastSampleAt = now;

  const uint8_t pins[] = {PIN_VOLTAGE1_ADC, PIN_VOLTAGE2_ADC, PIN_CURRENT_ADC};
  uint16_t readings[3];
  for (uint8_t i = 0; i < 3; ++i) readings[i] = analogReadMilliVolts(pins[i]);

  LOCK();
  for (uint8_t i = 0; i < 3; ++i) {
    VoltageChannel& channel = voltageChannels[i];
    channel.sumMilliVolts += readings[i];
    if (++channel.samples == VOLTAGE_SAMPLE_COUNT) {
      channel.averageMilliVolts =
          (channel.sumMilliVolts + VOLTAGE_SAMPLE_COUNT / 2) / VOLTAGE_SAMPLE_COUNT;
      channel.sumMilliVolts = 0;
      channel.samples = 0;
      channel.ready = true;
    }
  }
  UNLOCK();
}
static float inputVoltage(uint16_t adcMilliVolts) {
  return adcMilliVolts *
         (float)(VOLTAGE_DIVIDER_TOP_OHMS + VOLTAGE_DIVIDER_BOTTOM_OHMS) /
         VOLTAGE_DIVIDER_BOTTOM_OHMS / 1000.0f;
}
static float shuntCurrent(uint16_t adcMilliVolts) {
  return adcMilliVolts / 1000.0f / CURRENT_SHUNT_OHMS;
}

// Commit the current partial line into the circular history, then start a new
// partial line. The caller has already checked the fixed-buffer capacity.
static void commitLine(Console& c) {
  memcpy(c.lines[c.head], c.cur, c.clen); c.llen[c.head] = c.clen;
  c.head = (c.head + 1) % HIST_LINES; if (c.cnt < HIST_LINES) c.cnt++;
  c.clen = 0;
}
// Send staged raw bytes to all connected browsers that can accept a frame.
static void flushOut(Console& c) {
  if (!c.olen) return;
  for (auto& s : c.cli) if (s.used) {
    AsyncWebSocketClient* cl = c.ws->client(s.id);
    if (cl && cl->canSend()) cl->binary((const char*)c.out, c.olen);
  }
  c.olen = 0; c.lastFlush = millis();
}
// Drain one physical UART without blocking the main loop for an unbounded time.
// In parallel, retain raw bytes for HTTP polling, broadcast them over WebSocket,
// build a printable line history for OLED, and mark this port as recently active.
static void pump(Console& c, int idx) {
  if (!c.ser->available() && !c.olen) return;
  LOCK();
  int n = 0;
  while (c.ser->available() && n < 1024) {
    int b = c.ser->read(); n++;
    c.rx.push((uint8_t)b);
    if (c.olen >= OUT_MAX) flushOut(c);
    c.out[c.olen++] = (uint8_t)b;
    if (b == '\n') commitLine(c);
    else if (b != '\r') { if (c.clen >= LINE_MAX - 1) commitLine(c); c.cur[c.clen++] = (char)b; }
  }
  if (n) {
    lastUartActivity = millis();
    activeUartScreen = idx;
  }
  if (c.olen && (millis() - c.lastFlush >= FLUSH_MS || c.olen >= OUT_MAX / 2)) flushOut(c);
  UNLOCK();
}
// Remove WebSocket clients whose session expired or was revoked.
static void wsCheck() {   // закрывает сокеты с недействительной сессией
  LOCK();
  for (auto& c : con) for (auto& s : c.cli) if (s.used && findSessTok(s.tok) < 0) {
    s.used = false;
    AsyncWebSocketClient* cl = c.ws->client(s.id);
    if (cl) cl->close();
  }
  UNLOCK();
}
// Revoke all sessions for a user, except an optional session being used by the
// current password-change request, then close any now-invalid terminal sockets.
static void kickUser(int u, int except) {
  for (int i = 0; i < MAX_SESS; i++) if (sess[i].used && sess[i].user == u && i != except) sess[i].used = false;
  wsCheck();
}

// One handler is installed for each /ws/N endpoint. A browser's terminal bytes
// are validated/reassembled by ws_uart before being written to that UART.
static void onWs(int idx, AsyncWebSocketClient* cl, AwsEventType t, void* arg, uint8_t* data, size_t len) {
  Console& c = con[idx];
  if (t == WS_EVT_CONNECT) {
    int si = findSession((AsyncWebServerRequest*)arg);
    Serial.printf("[WS%d] connect session=%d\r\n", idx + 1, si);
    if (si < 0 || users[sess[si].user].must) { cl->close(); return; }
    LOCK();
    flushOut(c);
    WsCli* slot = nullptr;
    for (auto& s : c.cli) if (!s.used) { slot = &s; break; }
    if (!slot) { UNLOCK(); cl->close(); return; }
    // история + незавершённая строка
    String h; h.reserve(c.cnt * 80 + c.clen + 8);
    for (int i = 0; i < c.cnt; i++) {
      int k = (c.head - c.cnt + i + HIST_LINES) % HIST_LINES;
      h.concat(c.lines[k], c.llen[k]); h += "\r\n";
    }
    if (c.clen) h.concat(c.cur, c.clen);
    if (h.length()) cl->binary(h.c_str(), h.length());
    slot->used = true; slot->id = cl->id(); slot->user = sess[si].user; strcpy(slot->tok, sess[si].tok);
    UNLOCK();
  } else if (t == WS_EVT_DISCONNECT) {
    LOCK(); for (auto& s : c.cli) if (s.used && s.id == cl->id()) s.used = false; UNLOCK();
  } else if (t == WS_EVT_DATA) {
    AwsFrameInfo* i = (AwsFrameInfo*)arg;
    int u = -1; char tok[33] = {0};
    LOCK(); for (auto& s : c.cli) if (s.used && s.id == cl->id()) { u = s.user; strcpy(tok, s.tok); } UNLOCK();
    Serial.printf("[WS%d] data len=%u user=%d\r\n", idx + 1, (unsigned)len, u);
    if (u < 0 || findSessTok(tok) < 0 || users[u].role < R_RW) return;   // ro: тихо игнорируем
    size_t written = ws_uart::writeChunk(*c.ser, i->opcode, i->len, i->index, data, len);
    if (written != len) {
      Serial.printf("[UART%d] short write=%u expected=%u\r\n", idx + 1, (unsigned)written, (unsigned)len);
      return;
    }
    lastUartActivity = millis();
    activeUartScreen = idx;
    Serial.printf("[AUDIT] user=%s board=%d bytes=%u\r\n", users[u].name, idx + 1, (unsigned)len);
  }
}

// ===================================================================== relay outputs
// Relay state is persisted immediately so it can be restored after an ESP32 reset.
struct Relay { uint8_t pin; bool on; uint32_t cycleAt; };
static Relay relays[2] = {{PIN_RELAY1, true, 0}, {PIN_RELAY2, true, 0}};
static void relaySet(int i, bool on) {
  relays[i].on = on;
  digitalWrite(relays[i].pin, (on == (bool)RELAY_ACTIVE_HIGH) ? HIGH : LOW);
  prefs.putBool(i ? "r1" : "r0", on);
}
static void relayInit() {
  for (int i = 0; i < 2; i++) {
    bool on = prefs.getBool(i ? "r1" : "r0", true);
    relays[i].on = on;
    // Set the output latch before enabling output mode to minimize a software-
    // controlled pulse while restoring the saved relay state.
    digitalWrite(relays[i].pin, (on == (bool)RELAY_ACTIVE_HIGH) ? HIGH : LOW);
    pinMode(relays[i].pin, OUTPUT);
  }
}
static void relayTick() {
  for (int i = 0; i < 2; i++)
    if (relays[i].cycleAt && (int32_t)(millis() - relays[i].cycleAt) >= 0) { relays[i].cycleAt = 0; relaySet(i, true); }
}

// ===================================================================== WireGuard profiles and state machine
// The runtime form uses Arduino String/IP types; StoredVpnCfg is the validated,
// fixed-size representation kept in NVS and defined in vpn_profiles.h.
static const size_t VPN_TUNNEL_COUNT = vpn_profiles::COUNT;
static const size_t VPN_MAX_ROUTES = 8;
struct VpnCfg {
  bool ok;
  String priv, addr, pub, psk, host, allowed;
  int bits;
  uint16_t port, ka;
  wg_routes::Route routes[VPN_MAX_ROUTES];
  uint8_t routeCount;
};
using StoredVpnCfg = vpn_profiles::Config;
using StoredVpnSet = vpn_profiles::Store;
static StoredVpnSet storedVpns = {vpn_profiles::VERSION};

enum VpnState { V_OFF, V_WAIT_WIFI, V_WAIT_NTP, V_RESOLVE, V_START, V_UP };
struct VpnTunnel {
  VpnCfg cfg;
  VpnState state = V_OFF;
  WireGuardPsk wg;
  WiFiUDP keepaliveUdp;
  String remoteIp;
  IPAddress keepaliveTarget;
  uint32_t stateAt = 0, keepaliveAt = 0;
};
static VpnTunnel vpnTunnels[VPN_TUNNEL_COUNT];

static bool b64key(const String& v) {
  uint8_t d[48]; size_t ol = 0;
  return v.length() == 44 && v[43] == '=' &&
         mbedtls_base64_decode(d, sizeof d, &ol, (const uint8_t*)v.c_str(), v.length()) == 0 && ol == 32;
}
// Parse only IPv4 CIDRs. IPv6 and malformed prefixes are rejected explicitly.
static bool parseCidr(String s, IPAddress& ip, int& bits) {
  s.trim();
  if (s.indexOf(':') >= 0) return false;
  int sl = s.indexOf('/');
  String a = sl < 0 ? s : s.substring(0, sl);
  int dots = 0; for (size_t i = 0; i < a.length(); i++) { if (a[i] == '.') dots++; else if (!isdigit(a[i])) return false; }
  if (dots != 3) return false;
  bits = 32;
  if (sl >= 0) {
    String b = s.substring(sl + 1);
    if (!b.length()) return false;
    for (size_t i = 0; i < b.length(); i++) if (!isdigit(b[i])) return false;
    bits = b.toInt(); if (bits < 0 || bits > 32) return false;
  }
  return ip.fromString(a);
}
// Parse the supported wg-quick subset: one Interface, one Peer, IPv4 routes,
// keys, endpoint, and keepalive. Unused wg-quick keys are ignored; required
// fields are checked after parsing so incomplete profiles never reach NVS.
static bool parseWg(const String& txt, VpnCfg& o, String& err) {
  o = VpnCfg(); o.ka = 0; o.bits = 32;
  int sec = 0, peers = 0, pos = 0, ln = 0;
  bool hPriv = false, hAddr = false, hPub = false, hEp = false, hAl = false;
  while (pos < (int)txt.length()) {
    int e = txt.indexOf('\n', pos); if (e < 0) e = txt.length();
    String l = txt.substring(pos, e); pos = e + 1; ln++;
    int h = l.indexOf('#'); if (h >= 0) l = l.substring(0, h);
    l.trim(); if (!l.length()) continue;
    String at = "Строка " + String(ln) + ": ";
    if (l[0] == '[') {
      String s = l; s.toLowerCase();
      if (s == "[interface]") sec = 1;
      else if (s == "[peer]") { sec = 2; if (++peers > 1) { err = "Поддерживается только один [Peer]"; return false; } }
      else { err = at + "неизвестная секция " + l; return false; }
      continue;
    }
    int eq = l.indexOf('=');
    if (eq < 0 || sec == 0) { err = at + "ожидается Key = Value внутри секции"; return false; }
    String k = l.substring(0, eq), v = l.substring(eq + 1); k.trim(); v.trim(); k.toLowerCase();
    if (sec == 1) {
      if (k == "privatekey") { if (!b64key(v)) { err = at + "PrivateKey некорректен (нужен base64, 32 байта)"; return false; } o.priv = v; hPriv = true; }
      else if (k == "address") {
        int p = 0; bool got = false;
        while (p <= (int)v.length()) {
          int c = v.indexOf(',', p); if (c < 0) c = v.length();
          String a = v.substring(p, c); a.trim(); p = c + 1;
          if (!a.length()) continue;
          if (a.indexOf(':') >= 0) { err = at + "IPv6 в Address не поддерживается"; return false; }
          IPAddress ip; int b;
          if (!parseCidr(a, ip, b)) { err = at + "Address некорректен: " + a; return false; }
          if (!got) { o.addr = ip.toString(); o.bits = b; got = true; }
        }
        if (!got) { err = at + "Address пуст"; return false; }
        hAddr = true;
      }
      // DNS, MTU, ListenPort, PostUp и т.п. не применяются этой прошивкой.
    } else {
      if (k == "publickey") { if (!b64key(v)) { err = at + "PublicKey некорректен (нужен base64, 32 байта)"; return false; } o.pub = v; hPub = true; }
      else if (k == "presharedkey") {
        if (!b64key(v)) { err = at + "PresharedKey некорректен (нужен base64, 32 байта)"; return false; }
        o.psk = v;
      }
      else if (k == "endpoint") {
        int c = v.lastIndexOf(':');
        if (c <= 0 || v[0] == '[') { err = at + "Endpoint должен быть host:port (IPv4 или DNS-имя)"; return false; }
        String host = v.substring(0, c), port = v.substring(c + 1);
        for (size_t i = 0; i < host.length(); i++) if (!(isalnum(host[i]) || host[i] == '.' || host[i] == '-')) { err = at + "недопустимый символ в имени сервера"; return false; }
        for (size_t i = 0; i < port.length(); i++) if (!isdigit(port[i])) { err = at + "порт Endpoint некорректен"; return false; }
        int pn = port.toInt(); if (!host.length() || pn < 1 || pn > 65535) { err = at + "порт Endpoint некорректен"; return false; }
        o.host = host; o.port = pn; hEp = true;
      } else if (k == "allowedips") {
        int p = 0; String norm;
        while (p <= (int)v.length()) {
          int c = v.indexOf(',', p); if (c < 0) c = v.length();
          String a = v.substring(p, c); a.trim(); p = c + 1;
          if (!a.length()) continue;
          IPAddress ip; int b;
          if (a.indexOf(':') >= 0) { err = at + "IPv6 в AllowedIPs не поддерживается"; return false; }
          if (!parseCidr(a, ip, b)) { err = at + "AllowedIPs некорректен: " + a; return false; }
          if (o.routeCount >= VPN_MAX_ROUTES ||
              !wg_routes::parseIpv4Cidr(a.c_str(), o.routes[o.routeCount])) {
            err = at + "поддерживается не более восьми IPv4 AllowedIPs";
            return false;
          }
          ++o.routeCount;
          if (norm.length()) norm += ","; norm += a;
        }
        if (!norm.length()) { err = at + "AllowedIPs пуст"; return false; }
        o.allowed = norm; hAl = true;
      } else if (k == "persistentkeepalive") {
        if (v == "off") o.ka = 0;
        else {
          for (size_t i = 0; i < v.length(); i++) if (!isdigit(v[i])) { err = at + "PersistentKeepalive должен быть числом"; return false; }
          if (!v.length() || v.toInt() > 65535) { err = at + "PersistentKeepalive вне диапазона"; return false; }
          o.ka = v.toInt();
        }
      }
    }
  }
  if (!hPriv) { err = "Не найден PrivateKey"; return false; }
  if (!hAddr) { err = "Не найден Address"; return false; }
  if (peers == 0) { err = "Не найдена секция [Peer]"; return false; }
  if (!hPub) { err = "Не найден PublicKey"; return false; }
  if (!hEp) { err = "Не найден Endpoint"; return false; }
  if (!hAl) { err = "Не найден AllowedIPs"; return false; }
  o.ok = true; return true;
}
static bool storedTextValid(const char* text, size_t capacity) {
  return memchr(text, '\0', capacity) != nullptr;
}
static bool encodeVpn(const VpnCfg& cfg, StoredVpnCfg& stored) {
  if (!cfg.ok || cfg.priv.length() >= sizeof(stored.priv) || cfg.addr.length() >= sizeof(stored.addr) ||
      cfg.pub.length() >= sizeof(stored.pub) || cfg.psk.length() >= sizeof(stored.psk) ||
      cfg.host.length() >= sizeof(stored.host) || cfg.allowed.length() >= sizeof(stored.allowed)) return false;
  memset(&stored, 0, sizeof(stored));
  stored.configured = 1;
  cfg.priv.toCharArray(stored.priv, sizeof(stored.priv));
  cfg.addr.toCharArray(stored.addr, sizeof(stored.addr));
  cfg.pub.toCharArray(stored.pub, sizeof(stored.pub));
  cfg.psk.toCharArray(stored.psk, sizeof(stored.psk));
  cfg.host.toCharArray(stored.host, sizeof(stored.host));
  cfg.allowed.toCharArray(stored.allowed, sizeof(stored.allowed));
  stored.bits = cfg.bits;
  stored.port = cfg.port;
  stored.keepalive = cfg.ka;
  return true;
}
static bool decodeVpn(const StoredVpnCfg& stored, VpnCfg& cfg) {
  cfg = VpnCfg();
  if (!stored.configured || !storedTextValid(stored.priv, sizeof(stored.priv)) ||
      !storedTextValid(stored.addr, sizeof(stored.addr)) ||
      !storedTextValid(stored.pub, sizeof(stored.pub)) ||
      !storedTextValid(stored.psk, sizeof(stored.psk)) ||
      !storedTextValid(stored.host, sizeof(stored.host)) ||
      !storedTextValid(stored.allowed, sizeof(stored.allowed))) return false;
  cfg.priv = stored.priv;
  cfg.addr = stored.addr;
  cfg.pub = stored.pub;
  cfg.psk = stored.psk;
  cfg.host = stored.host;
  cfg.allowed = stored.allowed;
  cfg.bits = stored.bits;
  cfg.port = stored.port;
  cfg.ka = stored.keepalive;
  String routes = cfg.allowed;
  int pos = 0;
  while (pos <= static_cast<int>(routes.length())) {
    int end = routes.indexOf(',', pos);
    if (end < 0) end = routes.length();
    String item = routes.substring(pos, end);
    item.trim();
    if (cfg.routeCount >= VPN_MAX_ROUTES ||
        !wg_routes::parseIpv4Cidr(item.c_str(), cfg.routes[cfg.routeCount])) return false;
    ++cfg.routeCount;
    pos = end + 1;
  }
  cfg.ok = true;
  return true;
}
static bool persistVpnSet(const StoredVpnSet& candidate) {
  if (!vpn_profiles::validStore(candidate)) return false;
  return prefs.putBytes("wg_profiles", &candidate, sizeof(candidate)) == sizeof(candidate) &&
         prefs.getBytesLength("wg_profiles") == sizeof(candidate);
}
// Replace a profile only after validation and conflict checks succeed. The
// candidate set is persisted before runtime tunnel state is changed.
static bool saveVpn(size_t index, const VpnCfg& cfg) {
  if (index >= VPN_TUNNEL_COUNT) return false;
  StoredVpnSet candidate = storedVpns;
  candidate.version = vpn_profiles::VERSION;
  for (size_t other = 0; other < VPN_TUNNEL_COUNT; ++other) {
    if (other == index) continue;
    VpnCfg existing;
    if (!decodeVpn(candidate.configs[other], existing)) continue;
    for (size_t route = 0; route < cfg.routeCount; ++route)
      for (size_t oldRoute = 0; oldRoute < existing.routeCount; ++oldRoute)
        if (wg_routes::same(cfg.routes[route], existing.routes[oldRoute])) return false;
  }
  if (!encodeVpn(cfg, candidate.configs[index]) || !persistVpnSet(candidate)) return false;
  storedVpns = candidate;
  VpnTunnel& tunnel = vpnTunnels[index];
  if (tunnel.wg.is_initialized()) tunnel.wg.end();
  tunnel.keepaliveUdp.stop();
  tunnel.cfg = cfg;
  tunnel.remoteIp = "";
  tunnel.state = WiFi.status() == WL_CONNECTED ? V_WAIT_NTP : V_WAIT_WIFI;
  tunnel.stateAt = millis();
  return true;
}
// Remove exactly one tunnel and its routes; other profiles remain untouched.
static bool deleteVpn(size_t index) {
  if (index >= VPN_TUNNEL_COUNT) return false;
  StoredVpnSet candidate = storedVpns;
  if (!vpn_profiles::clear(candidate, index)) return false;
  if (!persistVpnSet(candidate)) return false;
  storedVpns = candidate;
  VpnTunnel& tunnel = vpnTunnels[index];
  if (tunnel.wg.is_initialized()) tunnel.wg.end();
  tunnel.keepaliveUdp.stop();
  tunnel.cfg = VpnCfg();
  tunnel.remoteIp = "";
  tunnel.state = V_OFF;
  return true;
}
// Load the current multi-profile format or migrate the legacy single-profile
// keys once, then put every valid configured tunnel in its initial state.
static void loadVpn() {
  StoredVpnSet stored = {};
  if (prefs.getBytesLength("wg_profiles") == sizeof(stored) &&
      prefs.getBytes("wg_profiles", &stored, sizeof(stored)) == sizeof(stored) &&
      vpn_profiles::validStore(stored)) {
    storedVpns = stored;
  } else {
    storedVpns.version = vpn_profiles::VERSION;
    if (prefs.getBool("wg_ok", false)) {
      VpnCfg legacy = {};
      legacy.ok = true;
      legacy.priv = prefs.getString("wg_priv");
      legacy.addr = prefs.getString("wg_addr");
      legacy.bits = prefs.getInt("wg_bits", 32);
      legacy.pub = prefs.getString("wg_pub");
      legacy.psk = prefs.getString("wg_psk");
      legacy.host = prefs.getString("wg_host");
      legacy.port = prefs.getUShort("wg_port", 51820);
      legacy.allowed = prefs.getString("wg_al");
      legacy.ka = prefs.getUShort("wg_ka", 0);
      String err;
      VpnCfg parsed;
      if (parseWg(String("[Interface]\nPrivateKey = ") + legacy.priv + "\nAddress = " + legacy.addr + "/" +
                      legacy.bits + "\n[Peer]\nPublicKey = " + legacy.pub + "\n" +
                      (legacy.psk.length() ? "PresharedKey = " + legacy.psk + "\n" : "") +
                      "Endpoint = " + legacy.host + ":" + legacy.port + "\nAllowedIPs = " +
                      legacy.allowed + "\nPersistentKeepalive = " + legacy.ka, parsed, err)) {
        encodeVpn(parsed, storedVpns.configs[0]);
      } else {
        Serial.printf("[VPN] Legacy profile migration failed: %s\r\n", err.c_str());
      }
    }
    if (!persistVpnSet(storedVpns)) Serial.println("[VPN] Could not persist profile migration");
  }

  for (size_t i = 0; i < VPN_TUNNEL_COUNT; ++i) {
    VpnTunnel& tunnel = vpnTunnels[i];
    if (!decodeVpn(storedVpns.configs[i], tunnel.cfg)) {
      if (storedVpns.configs[i].configured) Serial.printf("[VPN%u] Stored profile is invalid\r\n", static_cast<unsigned>(i + 1));
      tunnel.state = V_OFF;
      continue;
    }
    tunnel.state = V_WAIT_WIFI;
  }
}

static uint32_t toU32(const IPAddress& a) { return ((uint32_t)a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3]; }
static IPAddress fromU32(uint32_t v) { return IPAddress(v >> 24, (v >> 16) & 255, (v >> 8) & 255, v & 255); }

static void computeKaTarget(const VpnCfg& cfg, IPAddress& target) {
  IPAddress me; me.fromString(cfg.addr);
  int comma = cfg.allowed.indexOf(',');
  String first = cfg.allowed.substring(0, comma < 0 ? cfg.allowed.length() : comma);
  IPAddress ip; int b = 32; parseCidr(first, ip, b);
  if (b == 32) target = ip;
  else {
    int mb = cfg.bits == 32 ? 24 : cfg.bits;   // /32 у клиента: считаем сервер в той же /24 как .1
    uint32_t mask = mb == 0 ? 0 : (0xFFFFFFFFu << (32 - mb));
    target = fromU32((toU32(me) & mask) | 1);
  }
}
static const char* vpnName(const VpnTunnel& tunnel) {
  switch (tunnel.state) {
    case V_OFF: return tunnel.cfg.ok ? "off" : "не настроен";
    case V_WAIT_WIFI: return "ждёт WiFi";
    case V_WAIT_NTP: return "ждёт NTP";
    case V_RESOLVE: return "DNS";
    case V_START: return "подключение";
    case V_UP: return "up";
  }
  return "?";
}
static void vpnTick() {
  // Advance each tunnel independently; DNS, time synchronization, and handshake
  // setup are spread across loop iterations instead of blocking setup().
  for (size_t i = 0; i < VPN_TUNNEL_COUNT; ++i) {
    VpnTunnel& tunnel = vpnTunnels[i];
    VpnCfg& cfg = tunnel.cfg;
    switch (tunnel.state) {
    case V_OFF: break;
    case V_WAIT_WIFI:
      if (cfg.ok && WiFi.status() == WL_CONNECTED) {
        configTime(0, 0, "pool.ntp.org", "time.cloudflare.com");
        tunnel.stateAt = millis();
        tunnel.state = V_WAIT_NTP;
      }
      break;
    case V_WAIT_NTP:
      if (time(nullptr) > 1700000000) tunnel.state = V_RESOLVE;
      else if (millis() - tunnel.stateAt > 30000) {
        configTime(0, 0, "pool.ntp.org", "time.google.com");
        tunnel.stateAt = millis();
      }
      break;
    case V_RESOLVE: {
      IPAddress ip;
      if (ip.fromString(cfg.host) || WiFi.hostByName(cfg.host.c_str(), ip) == 1) {
        tunnel.remoteIp = ip.toString();
        tunnel.state = V_START;
      } else {
        tunnel.stateAt = millis() - 20000;
        tunnel.state = V_WAIT_NTP;
      }
      break;
    }
    case V_START: {
      IPAddress local; local.fromString(cfg.addr);
      computeKaTarget(cfg, tunnel.keepaliveTarget);
      uint8_t psk[32] = {};
      const uint8_t* pskPtr = nullptr;
      if (cfg.psk.length()) {
        size_t decodedLength = 0;
        if (mbedtls_base64_decode(psk, sizeof(psk), &decodedLength,
                                  reinterpret_cast<const uint8_t*>(cfg.psk.c_str()),
                                  cfg.psk.length()) != 0 || decodedLength != sizeof(psk)) {
          Serial.printf("[VPN%u] Stored PresharedKey is invalid\r\n", static_cast<unsigned>(i + 1));
          tunnel.state = V_OFF;
          break;
        }
        pskPtr = psk;
      }
      if (tunnel.wg.begin(local, cfg.priv.c_str(), tunnel.remoteIp.c_str(), cfg.pub.c_str(),
                          cfg.port, pskPtr, i, cfg.routes, cfg.routeCount)) {
        tunnel.state = V_UP;
        tunnel.keepaliveAt = millis();
      } else {
        tunnel.stateAt = millis() - 20000;
        tunnel.state = V_WAIT_NTP;
      }
      break;
    }
    case V_UP:
      if (cfg.ka && millis() - tunnel.keepaliveAt >= (uint32_t)cfg.ka * 1000UL) {
        tunnel.keepaliveAt = millis();
        tunnel.keepaliveUdp.beginPacket(tunnel.keepaliveTarget, 9);
        tunnel.keepaliveUdp.write((uint8_t)0);
        tunnel.keepaliveUdp.endPacket();
      }
      break;
    }
  }
}

// ===================================================================== Wi-Fi and mDNS
// The station retries saved profiles round-robin. The setup AP is brought up
// after a prolonged disconnect, and stopped again when station connectivity returns.
static bool apOn = false, mdnsOn = false;
static wifi_profiles::Profile wifiProfiles[wifi_profiles::MAX_PROFILES] = {};
static size_t wifiProfileCount = 0, wifiCurrentProfile = 0;
static uint32_t staLostAt = 0, wifiAttemptAt = 0;
static bool wifiAttemptStarted = false;

static void mdnsRestart() { if (mdnsOn) MDNS.end(); mdnsOn = false; }

// Persist only a validated profile set and verify the resulting NVS blob size.
static bool persistWifiProfiles(const wifi_profiles::Store& store) {
  if (!wifi_profiles::valid(store)) return false;
  return prefs.putBytes("wifi_v1", &store, sizeof(store)) == sizeof(store) &&
         prefs.getBytesLength("wifi_v1") == sizeof(store);
}

static void loadWifiProfiles() {
  wifi_profiles::Store stored = {};
  if (prefs.getBytesLength("wifi_v1") == sizeof(stored) &&
      prefs.getBytes("wifi_v1", &stored, sizeof(stored)) == sizeof(stored) &&
      wifi_profiles::valid(stored)) {
    wifiProfileCount = stored.count;
    memcpy(wifiProfiles, stored.profiles, sizeof(wifiProfiles));
    return;
  }

  // Missing/corrupt profile storage falls back to the compile-time network so
  // the device remains reachable for initial setup.
  if (prefs.isKey("wifi_v1")) Serial.println("[WiFi] Saved profiles invalid; restoring fallback");
  stored.version = wifi_profiles::STORE_VERSION;
  stored.count = 1;
  strncpy(stored.profiles[0].ssid, WIFI_SSID, sizeof(stored.profiles[0].ssid) - 1);
  strncpy(stored.profiles[0].password, WIFI_PASS, sizeof(stored.profiles[0].password) - 1);
  wifiProfileCount = 1;
  memcpy(wifiProfiles, stored.profiles, sizeof(wifiProfiles));
  if (!persistWifiProfiles(stored)) Serial.println("[WiFi] Could not migrate fallback profile to NVS");
}

static void connectWifiProfile(size_t index) {
  if (!wifiProfileCount) return;
  wifiCurrentProfile = index % wifiProfileCount;
  WiFi.disconnect(false, false);
  WiFi.mode(apOn ? WIFI_AP_STA : WIFI_STA);
  WiFi.begin(wifiProfiles[wifiCurrentProfile].ssid, wifiProfiles[wifiCurrentProfile].password);
  wifiAttemptAt = millis();
  wifiAttemptStarted = true;
  Serial.printf("[WiFi] Trying profile %u/%u: %s\r\n",
                static_cast<unsigned>(wifiCurrentProfile + 1),
                static_cast<unsigned>(wifiProfileCount),
                wifiProfiles[wifiCurrentProfile].ssid);
}

static void startAP() {
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(AP_SSID, AP_PASS);
  apOn = true;
  mdnsRestart();
}
static void netTick() {
  bool sta = WiFi.status() == WL_CONNECTED;
  if (sta) {
    staLostAt = 0;
    if (apOn) { WiFi.softAPdisconnect(true); WiFi.mode(WIFI_STA); apOn = false; mdnsRestart(); }
  } else {
    if (!staLostAt) staLostAt = millis();
    if (!apOn && millis() - staLostAt > AP_AFTER_LOST_MS) startAP();
    if (wifiProfileCount && wifiAttemptStarted &&
        static_cast<uint32_t>(millis() - wifiAttemptAt) >= 12000) {
      connectWifiProfile(wifi_profiles::nextIndex(wifiCurrentProfile, wifiProfileCount));
    }
  }
  if (!mdnsOn && (sta || apOn)) { if (MDNS.begin(HOSTNAME)) { MDNS.addService("http", "tcp", 80); mdnsOn = true; } }
}
static String curIp() { return WiFi.status() == WL_CONNECTED ? WiFi.localIP().toString() : (apOn ? WiFi.softAPIP().toString() : String("0.0.0.0")); }
static String vpnIpStr() {
  for (size_t i = 0; i < VPN_TUNNEL_COUNT; ++i)
    if (vpnTunnels[i].state == V_UP) return vpnTunnels[i].cfg.addr;
  return String();
}
static String vpnStatusText() {
  size_t configured = 0, connected = 0;
  for (const VpnTunnel& tunnel : vpnTunnels) {
    if (tunnel.cfg.ok) ++configured;
    if (tunnel.state == V_UP) ++connected;
  }
  if (!configured) return "none";
  return String("up ") + connected + "/" + configured;
}

// ===================================================================== OLED screens and idle game
static String oledPrev;
// Avoid rewriting an unchanged four-line screen over I2C.
static void oledShow(const String& a, const String& b, const String& c, const String& d) {
  String all = a + "|" + b + "|" + c + "|" + d;
  if (all == oledPrev) return;
  oledPrev = all;
  oled.clearBuffer(); oled.setFont(u8g2_font_5x7_t_cyrillic);
  oled.drawUTF8(0, 7, a.c_str()); oled.drawUTF8(0, 15, b.c_str());
  oled.drawUTF8(0, 23, c.c_str()); oled.drawUTF8(0, 31, d.c_str());
  oled.sendBuffer();
}
static uint32_t oledT = 0;
// screen 0 is status, 1/2 are terminal views, 3 is network/VPN, 4 is telemetry.
static int screen = 0;
static bool bootRelayMode = false;
static uint8_t bootRelaySelection = 0;
// Snake board is 32x8 logical cells, each rendered as a 4x4 pixel block.
// The body is stored head-first as linear cell indices.
static const uint8_t SNAKE_WIDTH = 32;
static const uint8_t SNAKE_HEIGHT = 8;
static const uint16_t SNAKE_CELLS = SNAKE_WIDTH * SNAKE_HEIGHT;
static uint16_t snakeBody[SNAKE_CELLS];
static uint16_t snakeLength = 4;
static int16_t snakeFood = -1;
static uint8_t snakeDirection = 1;
static uint32_t snakeStepAt = 0;
static bool snakeStarted = false;

static String cut(const String& s, size_t n) { return s.length() > n ? s.substring(0, n) : s; }
static String cutUtf8(const String& s, size_t maxChars) {
  size_t bytes = 0, chars = 0;
  while (bytes < s.length() && chars < maxChars) {
    const uint8_t c = s[bytes];
    const size_t width = c < 0x80 ? 1 : (c < 0xe0 ? 2 : (c < 0xf0 ? 3 : 4));
    if (bytes + width > s.length()) break;
    bytes += width;
    ++chars;
  }
  return bytes < s.length() ? s.substring(0, bytes) : s;
}
static void oledOverview(const String& a, const String& b, const String& c, const String& d) {
  String key = a + "|" + b + "|" + c + "|" + d;
  if (key == oledPrev) return;
  oledPrev = key;
  oled.clearBuffer();
  oled.setFont(u8g2_font_5x7_t_cyrillic);
  oled.drawUTF8(0, 7, cutUtf8(a, 21).c_str());
  oled.drawUTF8(0, 15, cutUtf8(b, 21).c_str());
  oled.drawUTF8(0, 23, cutUtf8(c, 21).c_str());
  oled.drawUTF8(0, 31, cutUtf8(d, 21).c_str());
  oled.sendBuffer();
}
// Convert a logical cell plus cardinal direction into a neighboring board
// cell. Hitting an edge is reported to the caller instead of wrapping around.
static bool snakeNextCell(uint16_t cell, uint8_t direction, uint16_t& next) {
  const int x = cell % SNAKE_WIDTH;
  const int y = cell / SNAKE_WIDTH;
  if (direction == 0) { if (!y) return false; next = cell - SNAKE_WIDTH; }
  else if (direction == 1) { if (x + 1 >= SNAKE_WIDTH) return false; next = cell + 1; }
  else if (direction == 2) { if (y + 1 >= SNAKE_HEIGHT) return false; next = cell + SNAKE_WIDTH; }
  else { if (!x) return false; next = cell - 1; }
  return true;
}
// The tail is considered free only when this move will advance it (no growth).
static bool snakeOccupied(uint16_t cell, bool tailMoves) {
  for (uint16_t i = 1; i < snakeLength; ++i) {
    if (tailMoves && i == snakeLength - 1) continue;
    if (snakeBody[i] == cell) return true;
  }
  return false;
}
// Place food only on a free cell. The full-board case is represented by -1.
static void snakePlaceFood() {
  if (snakeLength >= SNAKE_CELLS) { snakeFood = -1; return; }
  do { snakeFood = esp_random() % SNAKE_CELLS; }
  while (snakeOccupied(snakeFood, false) || snakeBody[0] == snakeFood);
}
// Start a fresh run in the middle of the display with the snake facing right.
static void snakeReset() {
  snakeLength = 4;
  snakeDirection = 1;
  const uint16_t head = (SNAKE_HEIGHT / 2) * SNAKE_WIDTH + SNAKE_WIDTH / 2;
  for (uint16_t i = 0; i < snakeLength; ++i) snakeBody[i] = head - i;
  snakePlaceFood();
  snakeStarted = true;
  snakeStepAt = millis();
}
// Breadth-first search finds the shortest route to food while treating the
// current body as blocked (apart from the tail, which moves on a normal step).
static bool snakeFindFoodDirection(uint8_t& direction) {
  static uint16_t queue[SNAKE_CELLS];
  static int16_t distance[SNAKE_CELLS];
  static uint8_t firstDirection[SNAKE_CELLS];
  for (uint16_t i = 0; i < SNAKE_CELLS; ++i) distance[i] = -1;
  uint16_t head = snakeBody[0], read = 0, write = 0;
  queue[write++] = head;
  distance[head] = 0;
  while (read < write) {
    const uint16_t cell = queue[read++];
    if (cell == snakeFood) { direction = firstDirection[cell]; return true; }
    for (uint8_t dir = 0; dir < 4; ++dir) {
      uint16_t next;
      if (!snakeNextCell(cell, dir, next) || distance[next] >= 0 ||
          (next != snakeFood && snakeOccupied(next, true))) continue;
      distance[next] = distance[cell] + 1;
      firstDirection[next] = cell == head ? dir : firstDirection[cell];
      queue[write++] = next;
    }
  }
  return false;
}
// If food is unreachable, estimate free space for each legal next move and
// choose the move that leaves the largest connected area.
static uint16_t snakeReachableSpace(uint16_t start, uint16_t oldHead, bool tailMoves) {
  static uint16_t queue[SNAKE_CELLS];
  static bool seen[SNAKE_CELLS];
  memset(seen, 0, sizeof(seen));
  uint16_t read = 0, write = 0;
  queue[write++] = start;
  seen[start] = true;
  while (read < write) {
    const uint16_t cell = queue[read++];
    for (uint8_t dir = 0; dir < 4; ++dir) {
      uint16_t next;
      if (!snakeNextCell(cell, dir, next) || seen[next] || next == oldHead ||
          snakeOccupied(next, tailMoves)) continue;
      seen[next] = true;
      queue[write++] = next;
    }
  }
  return write;
}
// Prefer the shortest food path; if none exists, prefer the safest open area.
static bool snakeChooseDirection(uint8_t& direction) {
  if (snakeFood >= 0 && snakeFindFoodDirection(direction)) return true;
  const uint16_t head = snakeBody[0];
  uint16_t bestSpace = 0;
  bool found = false;
  for (uint8_t offset = 0; offset < 4; ++offset) {
    const uint8_t dir = (snakeDirection + offset + 3) % 4;
    uint16_t next;
    if (!snakeNextCell(head, dir, next)) continue;
    const bool grows = next == snakeFood;
    if (snakeOccupied(next, !grows)) continue;
    const uint16_t space = snakeReachableSpace(next, head, !grows);
    if (!found || space > bestSpace) {
      found = true;
      bestSpace = space;
      direction = dir;
    }
  }
  return found;
}
// Advance game state at a fixed cadence. Collision/no legal move starts a new
// run; eating extends the body by retaining the previous tail position.
static void snakeTick() {
  if (!snakeStarted) snakeReset();
  if (snakeLength >= SNAKE_CELLS) return;
  if (millis() - snakeStepAt < 180) return;
  snakeStepAt = millis();
  uint8_t direction;
  if (!snakeChooseDirection(direction)) { snakeReset(); return; }
  uint16_t next;
  if (!snakeNextCell(snakeBody[0], direction, next)) { snakeReset(); return; }
  const bool eating = next == snakeFood;
  if (snakeOccupied(next, !eating)) { snakeReset(); return; }
  if (eating && snakeLength < SNAKE_CELLS) ++snakeLength;
  for (uint16_t i = snakeLength - 1; i > 0; --i) snakeBody[i] = snakeBody[i - 1];
  snakeBody[0] = next;
  snakeDirection = direction;
  if (eating) snakePlaceFood();
}
// Draw a blinking food pixel and the current body; game updates remain separate
// from rendering so the OLED loop can keep its own refresh cadence.
static void oledSnake() {
  snakeTick();
  const uint32_t frame = millis() / 300;
  const String key = "snake|" + String(frame) + "|" + String(snakeBody[0]) + "|" + String(snakeLength);
  if (key == oledPrev) return;
  oledPrev = key;
  oled.clearBuffer();
  if (snakeFood >= 0) {
    const uint8_t x = (snakeFood % SNAKE_WIDTH) * 4;
    const uint8_t y = (snakeFood / SNAKE_WIDTH) * 4;
    if (frame % 2) oled.drawDisc(x + 2, y + 2, 2);
    else { oled.drawPixel(x + 2, y + 1); oled.drawPixel(x + 1, y + 2); oled.drawPixel(x + 3, y + 2); oled.drawPixel(x + 2, y + 3); }
  }
  for (uint16_t i = 0; i < snakeLength; ++i) {
    const uint8_t x = (snakeBody[i] % SNAKE_WIDTH) * 4;
    const uint8_t y = (snakeBody[i] / SNAKE_WIDTH) * 4;
    if (i == 0) oled.drawBox(x, y, 4, 4);
    else oled.drawBox(x + 1, y + 1, 2, 2);
  }
  oled.sendBuffer();
}
static void oledRelayControl() {
  oledShow("Relay control", "Short: select R1/R2",
           String("Selected: R") + (bootRelaySelection + 1) + (relays[bootRelaySelection].on ? " ON" : " OFF"),
           "Long: confirm toggle");
}
static String cleanLine(const char* p, size_t n) {   // убирает ANSI и непечатные символы
  String o;
  for (size_t i = 0; i < n; i++) {
    uint8_t ch = p[i];
    if (ch == 0x1b) { if (i + 1 < n && p[i + 1] == '[') { i += 2; while (i < n && !(p[i] >= 0x40 && p[i] <= 0x7e)) i++; } continue; }
    if (ch >= 32 && ch < 127) o += (char)ch; else if (ch == '\t') o += ' ';
  }
  return o;
}
static void consoleLines(int idx, String out[4]) {   // последние 4 строки (включая незавершённую)
  Console& c = con[idx];
  String tmp[4]; int k = 0;
  LOCK();
  if (c.clen) tmp[k++] = cleanLine(c.cur, c.clen);
  for (int i = 0; i < c.cnt && k < 4; i++) {
    int j = (c.head - 1 - i + HIST_LINES) % HIST_LINES;
    tmp[k++] = cleanLine(c.lines[j], c.llen[j]);
  }
  UNLOCK();
  out[0] = String(terminalNames[idx]);
  for (int i = 0; i < 3; i++) out[3 - i] = i < k ? cut(tmp[i], 25) : String();
  if (k == 0) out[3] = "No data";
}
// OLED priority: relay-selection prompt, recent UART activity, idle game,
// manually selected terminal, telemetry, then status/network diagnostics.
static void oledTick() {
  if (bootRelayMode) {
    if (millis() - oledT < 100) return;
    oledT = millis();
    oledRelayControl();
    return;
  }
  const bool recentUart = activeUartScreen >= 0 && millis() - lastUartActivity < 8000;
  const bool idleAnimation = screen == 0 && millis() - lastUartActivity >= 8000;
  uint32_t per = recentUart || screen == 1 || screen == 2 ? 300 : (idleAnimation ? 180 : 1000);
  if (millis() - oledT < per) return;
  oledT = millis();
  if (recentUart) { String o[4]; consoleLines(activeUartScreen, o); oledShow(o[0], o[1], o[2], o[3]); return; }
  if (idleAnimation) { oledSnake(); return; }
  if (screen == 1 || screen == 2) { String o[4]; consoleLines(screen - 1, o); oledShow(o[0], o[1], o[2], o[3]); return; }
  if (screen == 3) {
    uint32_t s = millis() / 1000;
    const VpnCfg* firstConfigured = nullptr;
    for (const VpnTunnel& tunnel : vpnTunnels)
      if (tunnel.cfg.ok) { firstConfigured = &tunnel.cfg; break; }
    oledShow(cut(WiFi.status() == WL_CONNECTED ? WiFi.SSID() : String(AP_SSID), 25), String(HOSTNAME) + ".local",
             firstConfigured ? cut(firstConfigured->host + ":" + firstConfigured->port, 25) : String("VPN: none"),
             "up " + String(s / 3600) + "h" + String((s / 60) % 60) + "m heap " + String(ESP.getFreeHeap() / 1024) + "k");
    return;
  }
  if (screen == 4) {
    VoltageChannel snapshot[3];
    LOCK();
    memcpy(snapshot, voltageChannels, sizeof(snapshot));
    UNLOCK();
    oledShow("Voltage / current",
             snapshot[0].ready ? String("V1: ") + String(inputVoltage(snapshot[0].averageMilliVolts), 2) + " V" : "V1: waiting...",
             snapshot[1].ready ? String("V2: ") + String(inputVoltage(snapshot[1].averageMilliVolts), 2) + " V" : "V2: waiting...",
             snapshot[2].ready ? String("I: ") + String(shuntCurrent(snapshot[2].averageMilliVolts), 3) + " A" : "I: waiting...");
    return;
  }
  String l2 = WiFi.status() == WL_CONNECTED ? String("STA ") + WiFi.RSSI() + "dBm"
              : (apOn ? String("AP ") + AP_SSID + " cl:" + WiFi.softAPgetStationNum() : String("WiFi: нет"));
  l2.replace("нет", "none");
  String l3 = "VPN " + vpnStatusText();
  String l4 = String("Web:") + sessionCount() + " R1:" + (relays[0].on ? "ON" : "off") + " R2:" + (relays[1].on ? "ON" : "off");
  oledOverview("IP " + curIp(), l2, l3, l4);
}


// ===================================================================== BOOT button
// A debounced press is classified once as short or long; the release after a
// long press does not accidentally trigger a second short-press action.
struct Btn { uint8_t pin; bool down; bool longDone; uint32_t t; };
static Btn btns[1] = {{PIN_BTN_BOOT, false, false, 0}};
static void btnInit() { pinMode(btns[0].pin, INPUT_PULLUP); }
static void btnAction(int i, bool isLong) {
  lastUartActivity = millis();
  activeUartScreen = -1;
  if (!bootRelayMode) {
    if (isLong) {
      bootRelayMode = true;
      bootRelaySelection = 0;
    } else {
      screen = (screen + 1) % SCREENS;
    }
  } else if (isLong) {
    const int relay = bootRelaySelection;
    relays[relay].cycleAt = 0;
    relaySet(relay, !relays[relay].on);
    bootRelayMode = false;
    Serial.printf("[BTN] relay=%d toggle -> %s\r\n", relay + 1, relays[relay].on ? "ON" : "OFF");
  } else {
    bootRelaySelection ^= 1;
  }
  oledT = 0;
  oledPrev = "";
}
static void btnTick() {
  for (int i = 0; i < 1; i++) {
    Btn& b = btns[i];
    bool d = digitalRead(b.pin) == LOW;
    if (d && !b.down) {
      if (millis() - b.t < BTN_DEBOUNCE_MS) continue;
      b.down = true; b.longDone = false; b.t = millis();
    } else if (d && b.down && !b.longDone && millis() - b.t >= BTN_LONG_MS) {
      b.longDone = true; btnAction(i, true);
    } else if (!d && b.down) {
      b.down = false; bool wasLong = b.longDone; b.t = millis();
      if (!wasLong) btnAction(i, false);
    }
  }
}

// ===================================================================== HTTP API
// statusJson is intentionally read-only and omits credentials and key material.
static String statusJson() {
  bool sta = WiFi.status() == WL_CONNECTED;
  String j = "{\"ip\":\"" + curIp() + "\",\"mode\":\"" + (sta ? "STA" : (apOn ? "AP" : "-")) + "\",\"rssi\":" + String(sta ? WiFi.RSSI() : 0) +
             ",\"vpn\":\"" + jesc(vpnStatusText()) + "\",\"vpnIp\":\"" + vpnIpStr() + "\",\"sessions\":" + String(sessionCount()) +
             ",\"relays\":[" + (relays[0].on ? "1" : "0") + "," + (relays[1].on ? "1" : "0") +
             "],\"terminals\":[\"" + jesc(String(terminalNames[0])) + "\",\"" +
             jesc(String(terminalNames[1])) + "\"]}";
  return j;
}
static String voltageJson() {
  VoltageChannel snapshot[3];
  LOCK();
  memcpy(snapshot, voltageChannels, sizeof(snapshot));
  UNLOCK();

  String j = "{\"channels\":[";
  const uint8_t pins[] = {PIN_VOLTAGE1_ADC, PIN_VOLTAGE2_ADC};
  for (uint8_t i = 0; i < 2; ++i) {
    if (i) j += ",";
    const VoltageChannel& channel = snapshot[i];
    j += "{\"gpio\":" + String(pins[i]) + ",\"valid\":" +
         (channel.ready ? "true" : "false") + ",\"samples\":" +
         String(channel.ready ? VOLTAGE_SAMPLE_COUNT : channel.samples) +
         ",\"adc_millivolts\":";
    if (channel.ready) {
      j += String(channel.averageMilliVolts) + ",\"voltage\":" +
           String(inputVoltage(channel.averageMilliVolts), 3);
    } else {
      j += "null,\"voltage\":null";
    }
    j += "}";
  }
  j += "],\"shunt\":{\"gpio\":" + String(PIN_CURRENT_ADC) +
       ",\"valid\":" + (snapshot[2].ready ? "true" : "false") +
       ",\"samples\":" +
       String(snapshot[2].ready ? VOLTAGE_SAMPLE_COUNT : snapshot[2].samples) +
       ",\"voltage_millivolts\":";
  if (snapshot[2].ready) {
    j += String(snapshot[2].averageMilliVolts) + ",\"current_amps\":" +
         String(shuntCurrent(snapshot[2].averageMilliVolts), 3);
  } else {
    j += "null,\"current_amps\":null";
  }
  return j + "}}";
}
static bool consoleIndex(AsyncWebServerRequest* r, bool post, int& idx) {
  const AsyncWebParameter* p = r->getParam("idx", post);
  if (!p) return false;
  if (p->value() == "0") { idx = 0; return true; }
  if (p->value() == "1") { idx = 1; return true; }
  return false;
}
static bool vpnIndex(AsyncWebServerRequest* r, bool post, size_t& idx) {
  const AsyncWebParameter* p = r->getParam("idx", post);
  if (!p || p->value().length() != 1 || p->value()[0] < '0' ||
      p->value()[0] >= '0' + VPN_TUNNEL_COUNT) return false;
  idx = static_cast<size_t>(p->value()[0] - '0');
  return true;
}
static bool parseSequence(const String& value, uint64_t& sequence) {
  // Decimal-only parser with overflow detection for monotonically increasing
  // UART ring-buffer positions supplied by the browser.
  if (!value.length()) return false;
  sequence = 0;
  for (size_t i = 0; i < value.length(); ++i) {
    if (value[i] < '0' || value[i] > '9') return false;
    const uint8_t digit = value[i] - '0';
    if (sequence > (UINT64_MAX - digit) / 10) return false;
    sequence = sequence * 10 + digit;
  }
  return true;
}
// HTML is embedded in PROGMEM; use the flash-aware length when constructing
// the response rather than treating the program-memory pointer as RAM data.
static void sendPage(AsyncWebServerRequest* r, const char* html) {
  AsyncWebServerResponse* res = r->beginResponse(200, "text/html; charset=utf-8", (const uint8_t*)html, strlen_P(html));
  res->addHeader("Cache-Control", "no-store");
  r->send(res);
}

static void setupHttp() {
  // Static terminal assets are served from LittleFS; HTML application/login
  // pages are compiled into web_ui.h and selected according to the session.
  server.serveStatic("/assets/", LittleFS, "/assets/", "public,max-age=31536000,immutable");

  server.on("/", HTTP_GET, [](AsyncWebServerRequest* r) {
    int si = findSession(r);
    Serial.printf("[HTTP] GET / cookie=%s session=%d\r\n", r->hasHeader("Cookie") ? "yes" : "NO", si);
    for (size_t i = 0; i < r->headers(); i++) {
      const AsyncWebHeader* h = r->getHeader(i);
      if (h) Serial.printf("[HTTP]   hdr %s: %.40s\r\n", h->name().c_str(), h->value().c_str());
    }
    sendPage(r, si >= 0 ? APP_HTML : LOGIN_HTML);
  });

  // Login issues a random in-RAM session token and applies a bounded per-IP
  // lockout. A new admin account is marked must-change until /api/passwd succeeds.
  server.on("/api/login", HTTP_POST, [](AsyncWebServerRequest* r) {
    Fail* f = failFor((uint32_t)r->client()->remoteIP());
    if ((int32_t)(f->until - millis()) > 0 && f->n >= LOCK_FAILS) {
      sendJson(r, 429, "{\"error\":\"locked\",\"wait\":" + String((f->until - millis()) / 1000 + 1) + "}"); return;
    }
    String n = P(r, "user"), pw = P(r, "pass");
    int ui = findUser(n);
    static const User dummy = {};
    bool ok = ui >= 0 ? checkPw(users[ui], pw.c_str()) : (checkPw(dummy, pw.c_str()), false);
    Serial.printf("[LOGIN] user='%s' found=%d ok=%d\r\n", n.c_str(), ui >= 0, ok);
    if (!ok) {
      if (++f->n >= LOCK_FAILS) f->until = millis() + LOCK_MS;
      sendErr(r, 401, "bad"); return;
    }
    f->n = 0;
    char tok[33]; newSession(ui, tok);
    AsyncWebServerResponse* res = r->beginResponse(200, "application/json", String("{\"ok\":true,\"must\":") + (users[ui].must ? "true" : "false") + "}");
    res->addHeader("Set-Cookie", String("sid=") + tok + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=" + String(SESSION_MS / 1000));
    r->send(res);
  });
  server.on("/api/logout", HTTP_POST, [](AsyncWebServerRequest* r) {
    int si = findSession(r);
    if (si >= 0) { sess[si].used = false; wsCheck(); }
    AsyncWebServerResponse* res = r->beginResponse(200, "application/json", "{\"ok\":true}");
    res->addHeader("Set-Cookie", "sid=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
    r->send(res);
  });
  server.on("/api/me", HTTP_GET, [](AsyncWebServerRequest* r) {
    int si = auth(r, R_RO, true); if (si < 0) return;
    User& u = users[sess[si].user];
    sendJson(r, 200, String("{\"user\":\"") + u.name + "\",\"role\":\"" + ROLE_NAME[u.role] + "\",\"must\":" + (u.must ? "true" : "false") + "}");
  });
  server.on("/api/status", HTTP_GET, [](AsyncWebServerRequest* r) { if (auth(r, R_RO) < 0) return; sendJson(r, 200, statusJson()); });
  server.on("/api/voltage", HTTP_GET, [](AsyncWebServerRequest* r) {
    if (auth(r, R_RO) < 0) return;
    sendJson(r, 200, voltageJson());
  });
  // Terminal names are readable by authenticated clients for labels/status,
  // but only an administrator may persist replacements.
  server.on("/api/terminals", HTTP_GET, [](AsyncWebServerRequest* r) {
    if (auth(r, R_RO) < 0) return;
    sendJson(r, 200, String("{\"names\":[\"") + jesc(String(terminalNames[0])) + "\",\"" +
             jesc(String(terminalNames[1])) + "\"]}");
  });
  server.on("/api/terminals", HTTP_POST, [](AsyncWebServerRequest* r) {
    if (auth(r, R_ADMIN) < 0) return;
    char names[2][25] = {};
    for (int i = 0; i < 2; ++i) {
      String name = P(r, (String("name") + i).c_str());
      name.trim();
      if (!name.length() || name.length() > sizeof(names[i]) - 1) {
        sendErr(r, 400, "Имя терминала должно содержать 1–24 байта UTF-8");
        return;
      }
      for (size_t j = 0; j < name.length(); ++j) {
        const uint8_t c = name[j];
        if (c < 32 || c == 127) {
          sendErr(r, 400, "Имя терминала содержит недопустимый символ");
          return;
        }
      }
      memcpy(names[i], name.c_str(), name.length());
    }
    if (prefs.putBytes("termNames", names, sizeof(names)) != sizeof(names)) {
      sendErr(r, 500, "Не удалось сохранить имена терминалов");
      return;
    }
    memcpy(terminalNames, names, sizeof(terminalNames));
    sendJson(r, 200, String("{\"ok\":true,\"names\":[\"") + jesc(String(terminalNames[0])) + "\",\"" +
             jesc(String(terminalNames[1])) + "\"]}");
  });
  // Reading is sequence-based: clients ask for bytes after `since`; the RX
  // buffer clamps requests that have fallen behind its oldest retained byte.
  server.on("/api/uart/read", HTTP_GET, [](AsyncWebServerRequest* r) {
    if (auth(r, R_RO) < 0) return;
    int idx;
    if (!consoleIndex(r, false, idx)) { sendErr(r, 400, "Некорректный канал UART"); return; }
    uint64_t since = 0;
    const bool hasSince = r->hasParam("since");
    if (hasSince && !parseSequence(r->getParam("since")->value(), since)) {
      sendErr(r, 400, "Некорректная позиция UART"); return;
    }
    uint8_t bytes[512];
    uint64_t next;
    size_t count;
    LOCK();
    count = con[idx].rx.read(since, bytes, sizeof(bytes), next);
    UNLOCK();
    static const char HEX_DIGITS[] = "0123456789abcdef";
    String data; data.reserve(count * 2);
    for (size_t i = 0; i < count; ++i) {
      data += HEX_DIGITS[bytes[i] >> 4];
      data += HEX_DIGITS[bytes[i] & 0x0f];
    }
    char seq[24];
    snprintf(seq, sizeof(seq), "%llu", static_cast<unsigned long long>(next));
    sendJson(r, 200, String("{\"seq\":\"") + seq + "\",\"data\":\"" + data + "\"}");
  });
  // Writes are bounded per HTTP request. The browser batches terminal input
  // below this limit and sends binary-safe URL-encoded payloads.
  server.on("/api/uart/send", HTTP_POST, [](AsyncWebServerRequest* r) {
    int si = auth(r, R_RW); if (si < 0) return;
    int idx;
    if (!consoleIndex(r, true, idx)) { sendErr(r, 400, "Некорректный канал UART"); return; }
    String data = P(r, "data");
    if (!data.length() || data.length() > 256) { sendErr(r, 400, "Длина команды должна быть от 1 до 256 байт"); return; }
    size_t written = con[idx].ser->write((const uint8_t*)data.c_str(), data.length());
    if (written != data.length()) { sendErr(r, 500, "UART не принял все байты"); return; }
    lastUartActivity = millis();
    activeUartScreen = idx;
    Serial.printf("[UART%d] HTTP tx bytes=%u\r\n", idx + 1, (unsigned)written);
    sendJson(r, 200, String("{\"ok\":true,\"bytes\":") + String((unsigned)written) + "}");
  });
  // Register the base URI after /read and /send: AsyncWebServer matches
  // a base path as a prefix for nested paths, so ordering is significant.
  // Base UART settings routes are deliberately registered after the nested
  // read/send routes because this web server matches base paths as prefixes.
  server.on("/api/uart", HTTP_GET, [](AsyncWebServerRequest* r) {
    if (auth(r, R_ADMIN) < 0) return;
    String j = "[";
    static const char* parityNames[] = {"N", "E", "O"};
    for (int i = 0; i < 2; ++i) {
      if (i) j += ",";
      const UartSettings& s = uartSettings[i];
      j += String("{\"idx\":") + i + ",\"baud\":" + s.baud + ",\"bits\":" + s.bits +
           ",\"parity\":\"" + parityNames[s.parity] + "\",\"stop\":" + s.stop + "}";
    }
    sendJson(r, 200, j + "]");
  });
  server.on("/api/uart", HTTP_POST, [](AsyncWebServerRequest* r) {
    if (auth(r, R_ADMIN) < 0) return;
    int idx;
    if (!consoleIndex(r, true, idx)) { sendErr(r, 400, "Некорректный канал UART"); return; }
    uint64_t baud = 0, bits = 0, stop = 0;
    const String parity = P(r, "parity");
    if (!parseSequence(P(r, "baud"), baud) || baud < 300 || baud > 2000000 ||
        !parseSequence(P(r, "bits"), bits) || bits < 5 || bits > 8 ||
        !parseSequence(P(r, "stop"), stop) || (stop != 1 && stop != 2)) {
      sendErr(r, 400, "Некорректные параметры UART");
      return;
    }
    UartSettings settings = {};
    settings.baud = static_cast<uint32_t>(baud);
    settings.bits = static_cast<uint8_t>(bits);
    settings.parity = parity == "N" ? 0 : (parity == "E" ? 1 : (parity == "O" ? 2 : 255));
    settings.stop = static_cast<uint8_t>(stop);
    if (!validUartSettings(settings)) {
      sendErr(r, 400, "Скорость: 300–2000000, биты: 5–8, чётность: N/E/O, стоп-биты: 1/2");
      return;
    }
    const String key = String("uart") + idx;
    if (prefs.putBytes(key.c_str(), &settings, sizeof(settings)) != sizeof(settings)) {
      sendErr(r, 500, "Не удалось сохранить параметры UART");
      return;
    }
    uartSettings[idx] = settings;
    restartAt = millis() + 1500;
    sendJson(r, 200, "{\"ok\":true,\"restart\":true}");
  });

  // Password changes require the old password, rotate the salt, and revoke
  // other sessions for the affected user.
  server.on("/api/passwd", HTTP_POST, [](AsyncWebServerRequest* r) {
    int si = auth(r, R_RO, true); if (si < 0) return;
    User& u = users[sess[si].user];
    String o = P(r, "old"), n = P(r, "new");
    if (!checkPw(u, o.c_str())) { sendErr(r, 403, "Неверный текущий пароль"); return; }
    if (n.length() < 5 || n.length() > 64) { sendErr(r, 400, "Длина пароля 5–64 символа"); return; }
    if (n == "admin" || n == o) { sendErr(r, 400, "Выберите другой пароль"); return; }
    setPw(u, n.c_str()); u.must = 0; saveUsers();
    kickUser(sess[si].user, si);
    sendJson(r, 200, "{\"ok\":true}");
  });

  // Administrative routes never include password hashes or salts in responses.
  server.on("/api/users", HTTP_GET, [](AsyncWebServerRequest* r) {
    if (auth(r, R_ADMIN) < 0) return;
    String j = "["; bool f = true;
    for (auto& u : users) if (u.used) { if (!f) j += ","; f = false; j += String("{\"name\":\"") + u.name + "\",\"role\":\"" + ROLE_NAME[u.role] + "\"}"; }
    sendJson(r, 200, j + "]");
  });
  server.on("/api/wifi/profiles", HTTP_GET, [](AsyncWebServerRequest* r) {
    if (auth(r, R_ADMIN) < 0) return;
    String j = "[";
    for (size_t i = 0; i < wifiProfileCount; ++i) {
      if (i) j += ",";
      j += String("{\"ssid\":\"") + jesc(wifiProfiles[i].ssid) +
           "\",\"hasPassword\":" + (wifiProfiles[i].password[0] ? "true" : "false") + "}";
    }
    sendJson(r, 200, j + "]");
  });
  // An empty password inherits the previous password only for an unchanged
  // SSID. Open networks must be explicitly selected in the form.
  server.on("/api/wifi/profiles", HTTP_POST, [](AsyncWebServerRequest* r) {
    int si = auth(r, R_ADMIN); if (si < 0) return;
    wifi_profiles::Store store = {};
    store.version = wifi_profiles::STORE_VERSION;
    for (size_t i = 0; i < wifi_profiles::MAX_PROFILES; ++i) {
      String ssid = P(r, (String("ssid") + i).c_str());
      String password = P(r, (String("password") + i).c_str());
      String open = P(r, (String("open") + i).c_str());
      if (!ssid.length() && !password.length()) continue;
      if (!ssid.length() || ssid.length() > 32 || password.length() > 63 ||
          ssid.indexOf('\0') >= 0 || password.indexOf('\0') >= 0) {
        sendErr(r, 400, "SSID должен содержать 1–32 байта, пароль — не более 63 байт");
        return;
      }

      wifi_profiles::Profile& profile = store.profiles[store.count];
      memcpy(profile.ssid, ssid.c_str(), ssid.length());
      if (open == "1") {
        if (password.length()) { sendErr(r, 400, "Для открытой сети пароль должен быть пустым"); return; }
      } else if (password.length()) {
        memcpy(profile.password, password.c_str(), password.length());
      } else {
        if (!wifi_profiles::inheritPassword(wifiProfiles, wifiProfileCount, profile)) {
          sendErr(r, 400, "Введите пароль для новой сети или отметьте «Открытая сеть»");
          return;
        }
      }
      ++store.count;
    }
    if (!wifi_profiles::valid(store)) {
      sendErr(r, 400, "Добавьте от одной до пяти корректных точек доступа");
      return;
    }
    if (!persistWifiProfiles(store)) {
      sendErr(r, 500, "Не удалось сохранить Wi-Fi-профили в памяти устройства");
      return;
    }
    wifiProfileCount = store.count;
    memcpy(wifiProfiles, store.profiles, sizeof(wifiProfiles));
    wifiCurrentProfile = 0;
    sendJson(r, 200, String("{\"ok\":true,\"count\":") + store.count + "}");
    restartAt = millis() + 1500;
  });
  server.on("/api/users/add", HTTP_POST, [](AsyncWebServerRequest* r) {
    if (auth(r, R_ADMIN) < 0) return;
    String n = P(r, "name"), pw = P(r, "pass"); int ro = roleFrom(P(r, "role"));
    if (!validName(n)) { sendErr(r, 400, "Логин: 1–16 символов (латиница, цифры, _ - .)"); return; }
    if (findUser(n) >= 0) { sendErr(r, 409, "Пользователь уже существует"); return; }
    if (pw.length() < 5 || pw.length() > 64) { sendErr(r, 400, "Длина пароля 5–64 символа"); return; }
    if (ro < 0) { sendErr(r, 400, "Неверная роль"); return; }
    int slot = -1; for (int i = 0; i < MAX_USERS; i++) if (!users[i].used) { slot = i; break; }
    if (slot < 0) { sendErr(r, 409, "Достигнут лимит пользователей (8)"); return; }
    memset(&users[slot], 0, sizeof(User)); strcpy(users[slot].name, n.c_str());
    users[slot].role = ro; users[slot].used = 1; setPw(users[slot], pw.c_str()); saveUsers();
    sendJson(r, 200, "{\"ok\":true}");
  });
  server.on("/api/users/set", HTTP_POST, [](AsyncWebServerRequest* r) {
    int si = auth(r, R_ADMIN); if (si < 0) return;
    int ui = findUser(P(r, "name")); if (ui < 0) { sendErr(r, 404, "Нет такого пользователя"); return; }
    String pw = P(r, "pass"); String rs = P(r, "role"); int ro = rs.length() ? roleFrom(rs) : users[ui].role;
    if (ro < 0) { sendErr(r, 400, "Неверная роль"); return; }
    if (users[ui].role == R_ADMIN && ro != R_ADMIN && countAdmins() <= 1) { sendErr(r, 409, "Нельзя понизить последнего admin"); return; }
    if (pw.length() && (pw.length() < 5 || pw.length() > 64)) { sendErr(r, 400, "Длина пароля 5–64 символа"); return; }
    users[ui].role = ro;
    if (pw.length()) { setPw(users[ui], pw.c_str()); users[ui].must = 0; }
    saveUsers();
    if (pw.length()) kickUser(ui, ui == sess[si].user ? si : -1);
    sendJson(r, 200, "{\"ok\":true}");
  });
  server.on("/api/users/del", HTTP_POST, [](AsyncWebServerRequest* r) {
    int si = auth(r, R_ADMIN); if (si < 0) return;
    int ui = findUser(P(r, "name")); if (ui < 0) { sendErr(r, 404, "Нет такого пользователя"); return; }
    if (ui == sess[si].user) { sendErr(r, 409, "Нельзя удалить себя"); return; }
    if (users[ui].role == R_ADMIN && countAdmins() <= 1) { sendErr(r, 409, "Нельзя удалить последнего admin"); return; }
    users[ui].used = 0; saveUsers(); kickUser(ui, -1);
    sendJson(r, 200, "{\"ok\":true}");
  });

  // Web and BOOT relay actions share relaySet(), so hardware, NVS, and status
  // output remain synchronized regardless of the control surface.
  server.on("/api/relay", HTTP_POST, [](AsyncWebServerRequest* r) {
    int si = auth(r, R_RW); if (si < 0) return;
    int i = P(r, "idx").toInt(); String a = P(r, "act");
    if (i < 0 || i > 1) { sendErr(r, 400, "idx"); return; }
    if (a == "on") { relays[i].cycleAt = 0; relaySet(i, true); }
    else if (a == "off") { relays[i].cycleAt = 0; relaySet(i, false); }
    else if (a == "cycle") { relaySet(i, false); relays[i].cycleAt = (millis() + RELAY_CYCLE_OFF_MS) | 1; }
    else { sendErr(r, 400, "act"); return; }
    Serial.printf("[AUDIT] user=%s relay=%d act=%s\r\n", users[sess[si].user].name, i + 1, a.c_str());
    sendJson(r, 200, "{\"ok\":true}");
  });

  server.on("/api/vpn", HTTP_GET, [](AsyncWebServerRequest* r) {
    if (auth(r, R_ADMIN) < 0) return;
    String j = "{\"tunnels\":[";
    for (size_t i = 0; i < VPN_TUNNEL_COUNT; ++i) {
      if (i) j += ",";
      const VpnTunnel& tunnel = vpnTunnels[i];
      const VpnCfg& cfg = tunnel.cfg;
      j += String("{\"idx\":") + i + ",\"configured\":" + (cfg.ok ? "true" : "false") +
           ",\"state\":\"" + jesc(vpnName(tunnel)) + "\",\"ip\":\"" +
           (tunnel.state == V_UP ? cfg.addr : String()) + "\"";
      if (cfg.ok) {
        j += ",\"address\":\"" + cfg.addr + "/" + cfg.bits + "\",\"endpoint\":\"" +
             jesc(cfg.host) + ":" + cfg.port + "\",\"allowed\":\"" + jesc(cfg.allowed) +
             "\",\"keepalive\":" + cfg.ka + ",\"publicKey\":\"" + cfg.pub +
             "\",\"hasPresharedKey\":" + (cfg.psk.length() ? "true" : "false");
      }
      j += "}";
    }
    sendJson(r, 200, j + "]}");
  });
  // VPN configuration arrives as a bounded raw request body rather than form
  // fields. The body callback checks authorization and caps uploads at 4 KiB.
  server.on("/api/vpn", HTTP_POST,
    [](AsyncWebServerRequest* r) {
      if (auth(r, R_ADMIN) < 0) return;
      size_t index = 0;
      if (!vpnIndex(r, false, index)) { sendErr(r, 400, "Укажите idx от 0 до 2 в query string"); return; }
      if (!r->_tempObject) { sendErr(r, 400, "Пустой или слишком большой конфиг (макс. 4 КБ)"); return; }
      VpnCfg nc; String err;
      if (!parseWg(String((const char*)r->_tempObject), nc, err)) { sendErr(r, 400, err); return; }
      if (!saveVpn(index, nc)) {
        sendErr(r, 409, "Не удалось сохранить: ошибка памяти либо этот маршрут уже задан другим туннелем");
        return;
      }
      sendJson(r, 200, "{\"ok\":true,\"idx\":" + String(index) + "}");
    },
    nullptr,
    [](AsyncWebServerRequest* r, uint8_t* d, size_t len, size_t idx, size_t total) {
      int si = findSession(r);
      if (si < 0 || users[sess[si].user].role < R_ADMIN || users[sess[si].user].must) return;
      if (idx == 0) { if (total == 0 || total > 4096) return; r->_tempObject = malloc(total + 1); if (r->_tempObject) ((char*)r->_tempObject)[0] = 0; }
      if (!r->_tempObject) return;
      memcpy((char*)r->_tempObject + idx, d, len); ((char*)r->_tempObject)[idx + len] = 0;
    });
  server.on("/api/vpn/delete", HTTP_POST, [](AsyncWebServerRequest* r) {
    if (auth(r, R_ADMIN) < 0) return;
    size_t index = 0;
    if (!vpnIndex(r, true, index)) { sendErr(r, 400, "Укажите idx от 0 до 2"); return; }
    if (!deleteVpn(index)) { sendErr(r, 500, "Не удалось удалить конфигурацию WireGuard"); return; }
    sendJson(r, 200, String("{\"ok\":true,\"idx\":") + index + "}");
  });

  // Reject unauthenticated/first-login WebSocket upgrades before the UART
  // event handler. The two endpoints retain separate per-port client lists.
  auto flt = [](AsyncWebServerRequest* r) { int si = findSession(r); return si >= 0 && !users[sess[si].user].must; };
  ws0.setFilter(flt); ws1.setFilter(flt);
  ws0.onEvent([](AsyncWebSocket*, AsyncWebSocketClient* c, AwsEventType t, void* a, uint8_t* d, size_t l) { onWs(0, c, t, a, d, l); });
  ws1.onEvent([](AsyncWebSocket*, AsyncWebSocketClient* c, AwsEventType t, void* a, uint8_t* d, size_t l) { onWs(1, c, t, a, d, l); });
  server.addHandler(&ws0); server.addHandler(&ws1);
  server.onNotFound([](AsyncWebServerRequest* r) { sendErr(r, 404, "not found"); });
  server.begin();
}

// ===================================================================== device startup and cooperative main loop
void setup() {
  // Restore relay outputs before slower initialization, then load persistent
  // settings and initialize the display/UARTs before bringing up Wi-Fi.
  Serial.begin(115200);
  mux = xSemaphoreCreateRecursiveMutex();
  prefs.begin("gw", false);
  relayInit();
  loadTerminalNames();
  loadUartSettings();
  btnInit();
  delay(300);
  Serial.print("\r\n");   // начать с новой строки
  loadUsers(); loadVpn(); loadWifiProfiles();
  if (!LittleFS.begin(true)) {
    Serial.println("[FS] LittleFS mount failed; terminal assets unavailable");
  }
  oled.begin(); oled.setContrast(100);
  oledShow("OPi Console", "boot...", "", "");

  voltageInit();
  startUarts();
  con[0].ser = &Serial0; con[0].ws = &ws0;
  con[1].ser = &Serial1; con[1].ws = &ws1;

  static const char* parityNames[] = {"N", "E", "O"};
  Serial.printf("[UART] Pi#1 %lu %u%s%u; Pi#2 %lu %u%s%u\r\n",
                (unsigned long)uartSettings[0].baud, uartSettings[0].bits,
                parityNames[uartSettings[0].parity], uartSettings[0].stop,
                (unsigned long)uartSettings[1].baud, uartSettings[1].bits,
                parityNames[uartSettings[1].parity], uartSettings[1].stop);

  WiFi.persistent(false); WiFi.setAutoReconnect(false); WiFi.setHostname(HOSTNAME);
  WiFi.mode(WIFI_STA); connectWifiProfile(0);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < STA_TIMEOUT_MS) {
    oledShow("WiFi connecting", String((millis() - t0) / 1000) + " s",
             wifiProfiles[wifiCurrentProfile].ssid, ""); delay(200);
  }
  if (WiFi.status() != WL_CONNECTED) startAP();
  setupHttp();
  Serial.printf("Ready: %s\r\n", curIp().c_str());
}

void loop() {
  // Keep each subsystem non-blocking: service serial traffic first, then
  // advance network/VPN/relay/button/display state machines on every pass.
  pump(con[0], 0); pump(con[1], 1);
  netTick(); vpnTick(); relayTick(); btnTick(); oledTick(); voltageTick();
  static uint32_t chk = 0;
  if (millis() - chk > 2000) { chk = millis(); wsCheck(); ws0.cleanupClients(); ws1.cleanupClients(); }
  if (restartAt && (int32_t)(millis() - restartAt) >= 0) ESP.restart();
  delay(1);
}
