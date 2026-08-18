// presence-sniffer.ino
// Passive 802.11 probe-request sniffer for pi-presence-radar.
//
// v3.8 — the real parser. The offset showdown is settled: the rxctl header is
// 12 bytes (proven in v3.7 by a fully-parsed home-ssid beacon: FC 80 00,
// A1 broadcast, A2/A3 = <home-bssid>, timestamp, beacon interval 0x64,
// SSID tag "home-ssid" — and offset 12 scored a valid frame-control byte
// on all 1123/1123 frames). Every "0 probes / no beacons" conclusion from
// v3.2-v3.5 was this misalignment. Capture code is unchanged: sniff at boot,
// probe requests → RTC queue → MQTT, reboot.

#include <ESP8266WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
extern "C" {
#include <user_interface.h>   // promiscuous RX + RTC memory API
}

#include "config.h"

#define FRAME_TYPE_MGMT   0
#define SUBTYPE_PROBE_REQ 4

// The promiscuous callback on this SDK delivers 12 header bytes first:
// rxctl (RSSI at [0], rate, length...) then the 802.11 frame at +12.
// Proven empirically in v3.7 — a home-ssid beacon parsed perfectly
// only with PKT_OFF 12 (scoreboard: 1123/1123 valid frame-control bytes).
#define PKT_OFF 12

// cycle knobs (config.h can override)
#ifndef SNIFF_SESSION_MS
#define SNIFF_SESSION_MS 15000   // radio in capture mode at boot
#endif
#ifndef PH_HOME_MS
#define PH_HOME_MS 30000         // max time spent associating + reporting
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

// frame-type histogram, printed at session end — the diagnosis that finally
// works: beacons [8], probe_req [4], data/ctrl counts at the right alignment
static uint32_t hist_mgmt[16];      // per management subtype
static uint32_t hist_data = 0;
static uint32_t hist_ctrl = 0;

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
  if (len < PKT_OFF + 24) return;   // real frame must fit after the rxctl
  uint8_t *f = buf + PKT_OFF;
  uint16_t flen = len - PKT_OFF;

  burst_frames++;
  if (frame_type(f) == 0)      hist_mgmt[frame_subtype(f)]++;
  else if (frame_type(f) == 1) hist_ctrl++;
  else if (frame_type(f) == 2) hist_data++;
  if (frame_type(f) != FRAME_TYPE_MGMT)      return;
  if (frame_subtype(f) != SUBTYPE_PROBE_REQ) return;

  const uint8_t *mac = &f[10];         // address 2 == transmitter
  uint32_t now = millis();

  if (dbg_probe_n < 3) {                 // remember a few, for the serial proof
    memcpy(dbg_probe_mac[dbg_probe_n], mac, 6);
    dbg_probe_n++;
  }
  burst_probes++;
  for (int i = 0; i < SEEN_MAX; i++) {
    if (seen[i].last_seen != 0 && memcmp(seen[i].mac, mac, 6) == 0) {
      seen[i].last_seen = now;
      if (!seen[i].ssid[0]) parse_ssid(f, flen, seen[i].ssid, sizeof(seen[i].ssid));
      return;
    }
  }
  for (int i = 0; i < SEEN_MAX; i++) {
    if (seen[i].last_seen == 0) {        // fresh slot
      memcpy(seen[i].mac, mac, 6);
      seen[i].last_seen = now;
      parse_ssid(f, flen, seen[i].ssid, sizeof(seen[i].ssid));
      return;
    }
  }
  // table full: recycle the slot whose sighting was captured longest ago
  int oldest = 0;
  for (int i = 1; i < SEEN_MAX; i++)
    if (seen[i].last_seen < seen[oldest].last_seen) oldest = i;
  memcpy(seen[oldest].mac, mac, 6);
  seen[oldest].last_seen = now;
  parse_ssid(f, flen, seen[oldest].ssid, sizeof(seen[oldest].ssid));
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

  // Sniff FIRST, from a cold idle radio that has never associated — the
  // canonical ESP8266 sniffer state. Associating first (then disconnecting)
  // left the phy unable to lock the channel: sessions caught control + short
  // frames only, zero beacons. Associate happens later, in the report phase.
  WiFi.mode(WIFI_STA);                 // station opmode, NOT associated
  wifi_set_channel(SNIFF_CHANNEL);
  wifi_set_promiscuous_rx_cb(on_packet);
  wifi_promiscuous_enable(true);
  Serial.printf("sniffing on channel %d\n", wifi_get_channel());

  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setBufferSize(256);
  mqtt.setKeepAlive(60);

  phase = PH_SNIFF;
  phase_until = millis() + SNIFF_SESSION_MS;
}

void loop() {
  if (phase == PH_SNIFF) {
    if (millis() >= phase_until) {
      wifi_promiscuous_enable(false);
      commit_queue();
      Serial.printf("session done: %u frames, %u probes, ch=%u\n",
                    burst_frames, burst_probes, wifi_get_channel());
      Serial.printf("wifi status=%d ip=%s (did the SDK auto-connect?)\n",
                    WiFi.status(), WiFi.localIP().toString().c_str());
      Serial.printf("hist mgmt[0]=%lu [4]probe_req=%lu [5]probe_resp=%lu "
                    "[8]beacon=%lu [11]auth=%lu [12]deauth=%lu | data=%lu ctrl=%lu\n",
                    hist_mgmt[0], hist_mgmt[4], hist_mgmt[5], hist_mgmt[8],
                    hist_mgmt[11], hist_mgmt[12], hist_data, hist_ctrl);
      if (dbg_probe_n) {
        Serial.print("  probe macs: ");
        for (uint8_t i = 0; i < dbg_probe_n; i++)
          Serial.printf("%02x:%02x:%02x:%02x:%02x:%02x ",
                        dbg_probe_mac[i][0], dbg_probe_mac[i][1], dbg_probe_mac[i][2],
                        dbg_probe_mac[i][3], dbg_probe_mac[i][4], dbg_probe_mac[i][5]);
        Serial.println();
      }
      Serial.println("reporting...");
      phase = PH_HOME;
      phase_until = millis() + PH_HOME_MS;
      WiFi.begin(WIFI_SSID, WIFI_PASS);   // fresh association for the report
    }
    return;
  }

  // PH_HOME: associate + report, then reboot whatever happens (the RTC queue
  // survives, so a failed report retries next cycle).
  if (WiFi.status() == WL_CONNECTED && !mqtt.connected()) {
    digitalWrite(LED_BUILTIN, LOW);
    if (mqtt_connect()) {
      Serial.printf("mqtt connected to %s:%d\n", MQTT_HOST, MQTT_PORT);
      mqtt.publish("presence/online",
                   "{\"board\":\"" BOARD_ID "\",\"online\":true}", true);
      digitalWrite(LED_BUILTIN, HIGH);
    }
  }
  mqtt.loop();
  publish_queue();                     // drains RTC once the broker takes it

  if (millis() >= phase_until) {
    Serial.println("restarting");
    delay(100);
    ESP.restart();
  }
}