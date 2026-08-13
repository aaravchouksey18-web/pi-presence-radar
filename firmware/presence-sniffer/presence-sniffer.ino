// presence-sniffer.ino
// Passive 802.11 probe-request sniffer for pi-presence-radar.
//
// v2 — burst-cycle sniffing. The ESP8266 has a single radio: long periods
// of promiscuous capture make the station deaf (it misses beacons, ARP and
// TCP ACKs and drops off the network). So sensing runs in short bursts,
// MQTT connects first on a clean radio, and publishes happen only in the
// radio-free windows. See docs/build-log.md.

#include <ESP8266WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
extern "C" {
#include <user_interface.h>   // promiscuous receive API
}

#include "config.h"

#define FRAME_TYPE_MGMT   0
#define SUBTYPE_PROBE_REQ 4

// burst-cycle knobs (config.h can override)
#ifndef SNIFF_BURST_ON_MS
#define SNIFF_BURST_ON_MS  200   // radio in capture mode
#endif
#ifndef SNIFF_BURST_OFF_MS
#define SNIFF_BURST_OFF_MS 300   // radio free: beacons / ARP / TCP breathe
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

static bool burst_active = false;
static uint32_t burst_until = 0;

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
  if (frame_type(buf) != FRAME_TYPE_MGMT)      return;
  if (frame_subtype(buf) != SUBTYPE_PROBE_REQ) return;

  const uint8_t *mac = &buf[10];         // address 2 == transmitter
  uint32_t now = millis();

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

  wifi_set_channel(SNIFF_CHANNEL);
  wifi_set_promiscuous_rx_cb(on_packet);
  // capture stays OFF here: MQTT must connect on a clean radio first

  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setBufferSize(256);
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) {
    digitalWrite(LED_BUILTIN, LOW);
    delay(1000);
    return;
  }

  if (!mqtt.connected()) {
    digitalWrite(LED_BUILTIN, LOW);
    if (burst_active) {            // make sure capture is off before any TCP
      wifi_promiscuous_enable(false);
      burst_active = false;
    }
    if (mqtt_connect()) {
      Serial.printf("mqtt connected to %s:%d\n", MQTT_HOST, MQTT_PORT);
      digitalWrite(LED_BUILTIN, HIGH);
    }
    delay(2000);
    return;
  }

  mqtt.loop();

  uint32_t now = millis();
  if (!burst_active) {
    if (now >= burst_until) {
      wifi_promiscuous_enable(true);
      burst_active = true;
      burst_until = now + SNIFF_BURST_ON_MS;
    }
  } else {
    if (now >= burst_until) {
      wifi_promiscuous_enable(false);
      burst_active = false;
      burst_until = now + SNIFF_BURST_OFF_MS;
      publish_sightings();         // radio quiet: safe to talk TCP
    }
  }
}