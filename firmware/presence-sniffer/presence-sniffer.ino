// presence-sniffer.ino
// Passive 802.11 probe-request sniffer for pi-presence-radar.
//
// v3 — "offline-first sensor". Experiment E2 proved promiscuous capture
// permanently kills the ESP8266 station's TX: even on a clean radio, at any
// duty cycle, after the first capture session the board cannot send a single
// packet — only a fresh boot restores the stack (and a fresh boot ALWAYS
// connects). So the board stopped trying to stay connected while sniffing.
// Each cycle: boot fresh, phone home the previous session's sightings, sniff,
// stash results in RTC memory (survives reboot), then reboot. RTC storage
// also gives at-least-once delivery — sightings are only cleared after the
// broker acknowledges all of them. See docs/build-log.md.

#include <ESP8266WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
extern "C" {
#include <user_interface.h>   // promiscuous RX + RTC memory API
}

#include "config.h"

#define FRAME_TYPE_MGMT   0
#define SUBTYPE_PROBE_REQ 4

// cycle knobs (config.h can override)
#ifndef SNIFF_SESSION_MS
#define SNIFF_SESSION_MS 15000   // radio in capture mode before the reboot
#endif
#ifndef IDLE_MS
#define IDLE_MS 6000             // clean-radio window after boot, pre-sniff
#endif

// ---------------------------------------------------------------------------
// RTC queue: pending sightings survive the reboot. 256 bytes total:
// 1 magic + 1 count + 6 slots of {6 mac + 32 ssid}.
// ---------------------------------------------------------------------------
#define RTC_SLOTS 6
#define RTC_MAGIC 0xA5
#define RTC_ADDR  64          // user RTC memory starts here on ESP8266

struct rtc_slot_t { uint8_t mac[6]; char ssid[32]; };
struct rtc_q_t {
  uint8_t magic;              // RTC_MAGIC means the queue is valid
  uint8_t count;
  rtc_slot_t slots[RTC_SLOTS];
};

static void rtc_read(rtc_q_t *q) {
  if (!system_rtc_mem_read(RTC_ADDR, q, sizeof(rtc_q_t)) || q->magic != RTC_MAGIC) {
    memset(q, 0, sizeof(rtc_q_t));   // first boot / corrupted: start empty
  }
}

static void rtc_write(const rtc_q_t *q) {
  rtc_q_t tmp = *q;
  system_rtc_mem_write(RTC_ADDR, &tmp, sizeof(rtc_q_t));
}

static void rtc_clear() {
  rtc_q_t q;
  memset(&q, 0, sizeof(q));
  q.magic = RTC_MAGIC;
  rtc_write(&q);
}

// ---------------------------------------------------------------------------
// in-RAM seen table, filled by the sniffer callback during a capture session
// ---------------------------------------------------------------------------
#define SEEN_MAX 24
struct seen_t {
  uint8_t mac[6];
  uint32_t last_seen;         // millis() of the newest probe this session
  char ssid[33];
};
static seen_t seen[SEEN_MAX];
static uint32_t burst_frames = 0;   // every 802.11 frame the radio caught
static uint32_t burst_probes = 0;   // probe requests that hit the table
static uint8_t dbg_probe_mac[3][6]; // first probe MACs of the session, for proof
static uint8_t dbg_probe_n = 0;

WiFiClient net;
PubSubClient mqtt(net);

// --- 802.11 helpers --------------------------------------------------------

static uint8_t frame_type(uint8_t *f)    { return (f[0] >> 2) & 0x03; }
static uint8_t frame_subtype(uint8_t *f) { return (f[0] >> 4) & 0x0f; }

// pull the SSID out of a probe-request body (tagged params, tag id 0)
static void parse_ssid(uint8_t *frame, uint16_t len, char *out, size_t out_sz) {
  size_t off = 24;                       // 802.11 header on management frames
  while (off + 2 <= len) {
    uint8_t id   = frame[off];
    uint8_t tlen = frame[off + 1];
    if (off + 2 + tlen > len) break;
    if (id == 0x00 && tlen > 0) {
      size_t n = tlen < out_sz - 1 ? tlen : out_sz - 1;
      memcpy(out, &frame[off + 2], n);
      out[n] = '\0';
      return;
    }
    off += 2 + tlen;
  }
  out[0] = '\0';
}

// --- sniffer callback: stamp only, never touch TCP ---------------------------

static void ICACHE_RAM_ATTR on_packet(uint8_t *buf, uint16_t len) {
  if (len < 24) return;
  burst_frames++;
  if (frame_type(buf) != FRAME_TYPE_MGMT)      return;
  if (frame_subtype(buf) != SUBTYPE_PROBE_REQ) return;

  const uint8_t *mac = &buf[10];         // address 2 == transmitter
  uint32_t now = millis();

  if (dbg_probe_n < 3) {                 // remember a few, for the serial proof
    memcpy(dbg_probe_mac[dbg_probe_n], mac, 6);
    dbg_probe_n++;
  }
  burst_probes++;
  for (int i = 0; i < SEEN_MAX; i++) {
    if (seen[i].last_seen != 0 && memcmp(seen[i].mac, mac, 6) == 0) {
      seen[i].last_seen = now;
      if (!seen[i].ssid[0]) parse_ssid(buf, len, seen[i].ssid, sizeof(seen[i].ssid));
      return;
    }
  }
  for (int i = 0; i < SEEN_MAX; i++) {
    if (seen[i].last_seen == 0) {        // fresh slot
      memcpy(seen[i].mac, mac, 6);
      seen[i].last_seen = now;
      parse_ssid(buf, len, seen[i].ssid, sizeof(seen[i].ssid));
      return;
    }
  }
  // table full: recycle the slot whose sighting was captured longest ago
  int oldest = 0;
  for (int i = 1; i < SEEN_MAX; i++)
    if (seen[i].last_seen < seen[oldest].last_seen) oldest = i;
  memcpy(seen[oldest].mac, mac, 6);
  seen[oldest].last_seen = now;
  parse_ssid(buf, len, seen[oldest].ssid, sizeof(seen[oldest].ssid));
}

// --- publish the RTC queue right after boot (clean radio, fresh stack) --------

static void publish_queue() {
  static rtc_q_t q;
  rtc_read(&q);
  if (q.count == 0) return;

  int sent = 0;
  for (int i = 0; i < q.count; i++) {
    StaticJsonDocument<192> doc;
    doc["board"] = BOARD_ID;
    char mac_s[18];
    snprintf(mac_s, sizeof(mac_s), "%02x:%02x:%02x:%02x:%02x:%02x",
             q.slots[i].mac[0], q.slots[i].mac[1], q.slots[i].mac[2],
             q.slots[i].mac[3], q.slots[i].mac[4], q.slots[i].mac[5]);
    doc["mac"] = mac_s;
    if (q.slots[i].ssid[0]) doc["ssid"] = q.slots[i].ssid;

    char payload[192];
    serializeJson(doc, payload, sizeof(payload));
    if (mqtt.publish("presence/sighting", payload)) sent++;
  }
  Serial.printf("published %d/%d queued sightings\n", sent, q.count);
  if (sent == q.count) rtc_clear();       // broker took them all: safe to drop
}

// --- end of capture session: commit fresh sightings into the RTC queue -------

static void commit_queue() {
  static rtc_q_t q;
  rtc_read(&q);
  for (int i = 0; i < SEEN_MAX && q.count < RTC_SLOTS; i++) {
    if (seen[i].last_seen == 0) continue;         // nothing new this session
    memcpy(q.slots[q.count].mac, seen[i].mac, 6);
    snprintf(q.slots[q.count].ssid, sizeof(q.slots[q.count].ssid), "%s",
             seen[i].ssid);
    q.count++;
    seen[i].last_seen = 0;
  }
  q.magic = RTC_MAGIC;
  rtc_write(&q);
}

// --- MQTT --------------------------------------------------------------------

static bool mqtt_connect() {
  StaticJsonDocument<96> doc;
  doc["board"] = BOARD_ID;
  doc["online"] = false;              // LWT: published if we die mid-cycle
  char will[96];
  serializeJson(doc, will, sizeof(will));
  return mqtt.connect(BOARD_ID, "presence/online", 1, true, will);
}

// -----------------------------------------------------------------------------

enum { PH_HOME, PH_SNIFF };
static uint8_t phase = PH_HOME;
static uint32_t phase_until = 0;

void setup() {
  Serial.begin(115200);
  delay(200);
  pinMode(LED_BUILTIN, OUTPUT);
  Serial.println("boot");

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  Serial.println("connecting to wifi...");
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000) delay(250);
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("wifi failed this boot, retrying below");
  } else {
    Serial.printf("wifi up, ip %s, channel %d\n",
                  WiFi.localIP().toString().c_str(), wifi_get_channel());
  }
  // no wifi_set_channel here: the AP is already on the sniff channel, and
  // nothing network-dependent may happen after capture begins anyway

  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setBufferSize(256);
  mqtt.setKeepAlive(60);

  phase_until = millis() + IDLE_MS;
}

void loop() {
  if (phase == PH_HOME) {
    if (!mqtt.connected()) {
      digitalWrite(LED_BUILTIN, LOW);
      if (mqtt_connect()) {
        Serial.printf("mqtt connected to %s:%d\n", MQTT_HOST, MQTT_PORT);
        mqtt.publish("presence/online",
                     "{\"board\":\"" BOARD_ID "\",\"online\":true}", true);
        digitalWrite(LED_BUILTIN, HIGH);
      }
    }
    mqtt.loop();
    publish_queue();                    // drains RTC once the broker takes it

    if (millis() >= phase_until) {
      phase_until = millis() + SNIFF_SESSION_MS;
      phase = PH_SNIFF;
      burst_frames = burst_probes = 0;
      dbg_probe_n = 0;
      // Leave the AP first: while associated, the driver's RX filter only
      // forwards our own BSS's frames to the callback (health checks looked
      // fine but probes stayed at 0). Disconnected + channel pinned, the
      // radio delivers everything on channel 6.
      WiFi.disconnect();
      delay(200);
      wifi_set_channel(SNIFF_CHANNEL);
      wifi_set_promiscuous_rx_cb(on_packet);
      wifi_promiscuous_enable(true);
      Serial.println("sniffing (off-assoc)...");
    }
    return;
  }

  // PH_SNIFF: the stack is already dying by design — just capture and go.
  mqtt.loop();
  if (millis() >= phase_until) {
    wifi_promiscuous_enable(false);
    commit_queue();
    Serial.printf("session done: %u frames, %u probes\n", burst_frames, burst_probes);
    if (dbg_probe_n) {
      Serial.print("  probe macs: ");
      for (uint8_t i = 0; i < dbg_probe_n; i++)
        Serial.printf("%02x:%02x:%02x:%02x:%02x:%02x ",
                      dbg_probe_mac[i][0], dbg_probe_mac[i][1], dbg_probe_mac[i][2],
                      dbg_probe_mac[i][3], dbg_probe_mac[i][4], dbg_probe_mac[i][5]);
      Serial.println();
    }
    Serial.println("restarting");
    delay(100);
    ESP.restart();                      // fresh boot = fresh working stack
  }
}