// presence-sniffer.ino
// Passive 802.11 probe-request sniffer for pi-presence-radar.
//
// v2.2 — session sniffing. Promiscuous capture on this single radio doesn't
// just delay packets — it kills the station's whole network stack (even at
// 10% duty the board stopped answering ARP and never recovered). So the
// board alternates SNIFF sessions (radio fully in capture mode) with TALK
// sessions (radio clean, stack recovers, sightings phoned home). MQTT
// connects first on a clean radio; on boot and after every session the
// board self-heals: stick dead >10s and it bounces the WiFi stack.
// See docs/build-log.md.

#include <ESP8266WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
extern "C" {
#include <user_interface.h>   // promiscuous receive API
}

#include "config.h"

// --- TEMP EXPERIMENT E2 ------------------------------------------------------
// Keepalive-only client on channel 6, zero capture. Three firmware versions
// all connected once at boot then fell TCP-silent forever, scaling exactly
// with keepalive (22s/46s/90s) regardless of duty cycle. Question: is it
// wifi_set_channel(6) alone, or promiscuous mode? Flip this off for the real
// firmware after the experiment.
#define SNIFFER_DISABLED
// ----------------------------------------------------------------------------

#define FRAME_TYPE_MGMT   0
#define SUBTYPE_PROBE_REQ 4

// session-state knobs (config.h can override)
// The single-radio station dies (and stays dead) during promiscuous capture,
// so the board alternates: SNIFF sessions capture, TALK sessions give the
// stack a full breathing window and phone sightings home.
#ifndef SNIFF_DURATION_MS
#define SNIFF_DURATION_MS 4000   // radio in capture mode, contiguous
#endif
#ifndef SNIFF_GAP_MS
#define SNIFF_GAP_MS 8000        // radio free: full stack recovery + MQTT
#endif
#ifndef PUBLISH_GAP_MS
#define PUBLISH_GAP_MS 10000     // min gap between sightings of same MAC
#endif

// ---------------------------------------------------------------------------
// seen table: filled by the sniffer callback during a burst, drained by
// publish_sightings() in the quiet window. No TCP ever happens mid-capture.
// ---------------------------------------------------------------------------
#define SEEN_MAX 24
struct seen_t {
  uint8_t mac[6];
  uint32_t last_seen;   // millis() of the newest probe in a burst
  uint32_t last_pub;    // millis() of the last publish for this MAC
  char ssid[33];
};
static seen_t seen[SEEN_MAX];

WiFiClient net;
PubSubClient mqtt(net);

// session state machine: SS_SNIFF captures, SS_TALK phones home
enum { SS_SNIFF, SS_TALK };
static uint8_t session = SS_TALK;      // start quiet so MQTT connects first
static uint32_t session_until = 0;
static uint8_t clean_fail = 0;         // consecutive clean-radio MQTT failures

// channel-activity counters (reported on the serial monitor)
static uint32_t burst_frames = 0;   // every 802.11 frame the radio catches
static uint32_t burst_probes = 0;   // probe requests addressed to the table

// --- 802.11 helpers --------------------------------------------------------

static uint8_t frame_type(uint8_t *f)    { return (f[0] >> 2) & 0x03; }
static uint8_t frame_subtype(uint8_t *f) { return (f[0] >> 4) & 0x0f; }

// pull the SSID out of a probe-request body (tagged parameters, tag id 0)
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

  burst_probes++;
  for (int i = 0; i < SEEN_MAX; i++) {
    if (seen[i].last_pub != 0 && memcmp(seen[i].mac, mac, 6) == 0) {
      seen[i].last_seen = now;
      if (!seen[i].ssid[0]) parse_ssid(buf, len, seen[i].ssid, sizeof(seen[i].ssid));
      return;
    }
  }
  for (int i = 0; i < SEEN_MAX; i++) {
    if (seen[i].last_pub == 0) {         // fresh slot
      memcpy(seen[i].mac, mac, 6);
      seen[i].last_seen   = now;
      seen[i].last_pub    = now;
      parse_ssid(buf, len, seen[i].ssid, sizeof(seen[i].ssid));
      return;
    }
  }
  // table full: recycle the slot whose sighting was published longest ago
  int oldest = 0;
  for (int i = 1; i < SEEN_MAX; i++)
    if (seen[i].last_pub < seen[oldest].last_pub) oldest = i;
  memcpy(seen[oldest].mac, mac, 6);
  seen[oldest].last_seen = now;
  parse_ssid(buf, len, seen[oldest].ssid, sizeof(seen[oldest].ssid));
}

// --- publish, only with a clean radio -----------------------------------------

static void publish_sightings() {
  uint32_t now = millis();
  int n = 0;
  for (int i = 0; i < SEEN_MAX; i++) {
    if (seen[i].last_pub == 0 || seen[i].last_seen == 0) continue;
    if (now - seen[i].last_pub < PUBLISH_GAP_MS) continue;

    StaticJsonDocument<192> doc;
    doc["board"] = BOARD_ID;
    char mac_s[18];
    snprintf(mac_s, sizeof(mac_s), "%02x:%02x:%02x:%02x:%02x:%02x",
             seen[i].mac[0], seen[i].mac[1], seen[i].mac[2],
             seen[i].mac[3], seen[i].mac[4], seen[i].mac[5]);
    doc["mac"] = mac_s;
    if (seen[i].ssid[0]) doc["ssid"] = seen[i].ssid;

    char payload[192];
    serializeJson(doc, payload, sizeof(payload));
    mqtt.publish("presence/sighting", payload);

    seen[i].last_pub = now;
    seen[i].last_seen = 0;
    seen[i].ssid[0] = '\0';
    n++;
  }
  if (n > 0) Serial.printf("sightings flushed: %d\n", n);
}

// --- MQTT --------------------------------------------------------------------

static bool mqtt_connect() {
  StaticJsonDocument<96> doc;
  doc["board"] = BOARD_ID;
  doc["online"] = false;              // LWT: published if we die without saying bye
  char will[96];
  serializeJson(doc, will, sizeof(will));
  return mqtt.connect(BOARD_ID, "presence/online", 1, true, will);
}

// -----------------------------------------------------------------------------

void setup() {
  Serial.begin(115200);
  delay(200);
  pinMode(LED_BUILTIN, OUTPUT);

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  Serial.println("connecting to wifi...");
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000) delay(250);
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("wifi failed, retrying in loop()");
  } else {
    Serial.printf("wifi up, ip %s, channel %d\n",
                  WiFi.localIP().toString().c_str(), wifi_get_channel());
  }

  wifi_set_channel(SNIFF_CHANNEL);          // E2: kept, under test
#ifndef SNIFFER_DISABLED
  wifi_set_promiscuous_rx_cb(on_packet);
  // capture stays OFF here: MQTT must connect on a clean radio first
#endif

  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setBufferSize(256);
  mqtt.setKeepAlive(60);       // the stack dies during capture sessions;
                               // 60s gives the TALK windows room to revive
                               // it and get a PINGREQ out in time
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) {
    digitalWrite(LED_BUILTIN, LOW);
    static uint32_t wd_since = 0;
    if (wd_since == 0) wd_since = millis();
    else if (millis() - wd_since > 10000) {   // stuck >10s: bounce the stack
      wd_since = 0;
      WiFi.disconnect();
      WiFi.begin(WIFI_SSID, WIFI_PASS);
      Serial.println("wifi bounced");
    }
    delay(1000);
    return;
  }

  if (!mqtt.connected()) {
    digitalWrite(LED_BUILTIN, LOW);
    wifi_promiscuous_enable(false);   // dial out on a clean radio
    session = SS_TALK;
    session_until = millis() + SNIFF_GAP_MS;
    if (mqtt_connect()) {
      Serial.printf("mqtt connected to %s:%d\n", MQTT_HOST, MQTT_PORT);
      // retained online: the offline will replaces it on unexpected death,
      // so the dashboard never shows a stale state
      mqtt.publish("presence/online",
                   "{\"board\":\"" BOARD_ID "\",\"online\":true}", true);
      digitalWrite(LED_BUILTIN, HIGH);
      clean_fail = 0;
    } else if (++clean_fail >= 3) {
      Serial.println("mqtt stuck on clean radio: bouncing wifi");
      WiFi.disconnect();
      WiFi.begin(WIFI_SSID, WIFI_PASS);
      clean_fail = 0;
    }
    delay(2000);
    return;
  }
  clean_fail = 0;

  mqtt.loop();

#ifdef SNIFFER_DISABLED
  // E2: pure keepalive client — no session machinery, no promiscuous toggles
  delay(500);
  return;
#endif

  uint32_t now = millis();
  if (session == SS_SNIFF) {
    if (now >= session_until) {
      wifi_promiscuous_enable(false);
      session = SS_TALK;
      session_until = now + SNIFF_GAP_MS;
      publish_sightings();          // queue drained on a quiet radio
      report_channel();
    }
  } else {
    if (now >= session_until) {
      wifi_promiscuous_enable(true);
      session = SS_SNIFF;
      session_until = now + SNIFF_DURATION_MS;
    }
  }
}

// print channel activity every ~5s so the serial monitor has a pulse
static void report_channel() {
  static uint32_t last_report = 0;
  uint32_t now = millis();
  if (now - last_report < 5000) return;
  Serial.printf("[sniff] ch%d: %u frames caught, %u probes seen\n",
                SNIFF_CHANNEL, burst_frames, burst_probes);
  last_report = now;
  burst_frames = burst_probes = 0;
}