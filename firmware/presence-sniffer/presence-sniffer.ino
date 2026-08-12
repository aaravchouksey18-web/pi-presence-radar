// presence-sniffer.ino
// Passive 802.11 probe-request sniffer for pi-presence-radar.
//
// The board joins the home Wi-Fi as a station (so it can reach the MQTT
// broker) and also enables promiscuous receive. Probe requests — the
// management frames phones shout to discover networks — are parsed for the
// transmitter MAC and the SSID being probed, then published to the hub.
//
// Known limitation: the ESP8266 promiscuous callback doesn't expose RSSI
// (frame body only), so no signal strength yet. See docs/build-log.md.

#include <ESP8266WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
extern "C" {
#include <user_interface.h>   // promiscuous receive API
}

#include "config.h"

#define FRAME_TYPE_MGMT   0
#define SUBTYPE_PROBE_REQ 4

// ---------------------------------------------------------------------------
// rate limiting: phones burst several probe requests per second, so each MAC
// is published at most once per PUBLISH_GAP_MS. small fixed snapshot table.
// ---------------------------------------------------------------------------
#define TRACKED_MACS 16
struct sighting_t {
  uint8_t mac[6];
  uint32_t last_pub;   // millis()
};
static sighting_t table[TRACKED_MACS];

WiFiClient net;
PubSubClient mqtt(net);

// --- 802.11 helpers --------------------------------------------------------

static uint8_t frame_type(uint8_t *f)    { return (f[0] >> 2) & 0x03; }
static uint8_t frame_subtype(uint8_t *f) { return (f[0] >> 4) & 0x0f; }

// scan tagged parameters in the frame body for the SSID (tag id 0x00)
static void parse_ssid(uint8_t *frame, uint16_t len, char *out, size_t out_sz) {
  size_t off = 24;                       // 802.11 header on management frames
  while (off + 2 <= len) {
    uint8_t id    = frame[off];
    uint8_t tlen  = frame[off + 1];
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

// --- sniffer callback --------------------------------------------------------

static void ICACHE_RAM_ATTR on_packet(uint8_t *buf, uint16_t len) {
  if (len < 24) return;
  if (frame_type(buf) != FRAME_TYPE_MGMT)      return;
  if (frame_subtype(buf) != SUBTYPE_PROBE_REQ) return;

  const uint8_t *mac = &buf[10];         // address 2 == transmitter

  uint32_t now = millis();
  int slot = -1;
  for (int i = 0; i < TRACKED_MACS; i++) {
    if (memcmp(table[i].mac, mac, 6) == 0) {
      if (now - table[i].last_pub < PUBLISH_GAP_MS) return;  // already seen
      table[i].last_pub = now;
      slot = i;
      break;
    }
  }
  if (slot == -1) {                      // new MAC: grab a free slot
    for (int i = 0; i < TRACKED_MACS; i++) {
      if (table[i].last_pub == 0) {
        memcpy(table[i].mac, mac, 6);
        table[i].last_pub = now;
        slot = i;
        break;
      }
    }
  }
  if (slot == -1) return;                // table full, drop this one

  char ssid[33];
  parse_ssid(buf, len, ssid, sizeof(ssid));

  char mac_s[18];
  snprintf(mac_s, sizeof(mac_s), "%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

  StaticJsonDocument<192> doc;
  doc["board"] = BOARD_ID;
  doc["mac"]   = mac_s;
  doc["ssid"]  = ssid;
  char payload[192];
  serializeJson(doc, payload, sizeof(payload));

  mqtt.publish("presence/sighting", payload);
}

// --- MQTT ---------------------------------------------------------------------

static bool mqtt_connect() {
  StaticJsonDocument<96> doc;
  doc["board"] = BOARD_ID;
  char will[96];
  serializeJson(doc, will, sizeof(will));
  return mqtt.connect(BOARD_ID, "presence/online", 1, true, will);
}

// -------------------------------------------------------------------------------

void setup() {
  Serial.begin(115200);
  delay(200);

  pinMode(LED_BUILTIN, OUTPUT);

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);                  // keep the radio awake for sniffing
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  Serial.println("connecting to wifi...");
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000) {
    delay(250);
  }
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("wifi failed, retrying in loop()");
  } else {
    Serial.printf("wifi up, ip %s, channel %d\n",
                  WiFi.localIP().toString().c_str(), wifi_get_channel());
  }

  wifi_set_channel(SNIFF_CHANNEL);       // lock onto the AP's channel
  wifi_set_promiscuous_rx_cb(on_packet);
  wifi_promiscuous_enable(true);
  Serial.printf("sniffing on channel %d\n", SNIFF_CHANNEL);

  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setBufferSize(256);
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) {
    digitalWrite(LED_BUILTIN, LOW);
    delay(1000);
    return;                              // will re-scan in setup? no - keep light
  }

  if (!mqtt.connected()) {
    digitalWrite(LED_BUILTIN, LOW);
    if (mqtt_connect()) {
      Serial.printf("mqtt connected to %s:%d\n", MQTT_HOST, MQTT_PORT);
      digitalWrite(LED_BUILTIN, HIGH);
    }
    delay(2000);
    return;
  }
  mqtt.loop();
}