// presence-sniffer.ino
// Passive 802.11 probe-request sniffer for pi-presence-radar.
//
// v3.7 — offsets 12/28 showdown + full labeled dump. v3.6 scoring split 22/28
// (6 apart, suspicious) and missed K=12 entirely — yet frame0 dumps showed the
// router MAC <home-bssid> right behind an FF:FF:FF:FF:FF:FF broadcast with
// "80 00" (the exact beacon frame-control) sitting at offset 12. This build
// adds K=12 to the scoreboard, prints full 64-byte dumps with index labels,
// and a labeled FC/dur/A1/A2/A3 parse at both 12 and 28 — read, don't guess.

#include <ESP8266WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
extern "C" {
#include <user_interface.h>   // promiscuous RX + RTC memory API
}

#include "config.h"

#define FRAME_TYPE_MGMT   0
#define SUBTYPE_PROBE_REQ 4

// Espressif core 3.x prepends a wifi_pkt_rx_ctrl_t header to every frame
// delivered to the promiscuous callback — but its size is compiler/SDK
// dependent (24? 25? 28?). Rather than guess: score candidate offsets by how
// often they land on a plausible 802.11 frame-control byte (version 0, type
// != reserved), and dump raw bytes so the alignment can be read directly.
#define CAND_N 12
static const uint8_t cand_off[CAND_N] = {8, 10, 12, 14, 16, 20, 22, 24, 25, 26, 28, 32};
static uint32_t cand_score[CAND_N];

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

// frame-type histogram, printed at session end to see exactly what the radio
// delivers (was: three theories, still 0 probes → count everything)
static uint32_t hist_mgmt[16];      // per management subtype
static uint32_t hist_data = 0;
static uint32_t hist_ctrl = 0;

// raw-frame sampler: first 2 frames' raw bytes from offset 0 (rxctl + all),
// so the true 802.11 header position can be read directly from the hex
static uint8_t dbg_raw[2][64];
static uint8_t dbg_raw_n = 0;
static uint16_t dbg_max_len = 0;

// labeled parses at the two prime suspects (12: beacon FC 0x80 seen there;
// 28: top scorer) — print both, read the winner off the serial
struct dbg_parse_t {
  uint8_t fc0, fc1, dur0, dur1;
  uint8_t a1[6], a2[6], a3[6];
  uint16_t seq;
};
static dbg_parse_t dbg_p12[2], dbg_p28[2];

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
  if (len < 40) return;

  burst_frames++;
  if (dbg_raw_n < 2) {                 // raw bytes from offset 0, for the hexdump
    uint16_t n = len < 64 ? len : 64;
    memcpy(dbg_raw[dbg_raw_n], buf, n);
    // labeled parses at K=12 and K=28 for the same frame
    for (int K = 12, sl = 0; K <= 28; K += 16, sl++) {
      dbg_parse_t *p = sl == 0 ? &dbg_p12[dbg_raw_n] : &dbg_p28[dbg_raw_n];
      p->fc0 = buf[K]; p->fc1 = buf[K + 1];
      p->dur0 = buf[K + 2]; p->dur1 = buf[K + 3];
      memcpy(p->a1, &buf[K + 4], 6);
      memcpy(p->a2, &buf[K + 10], 6);
      memcpy(p->a3, &buf[K + 16], 6);
      p->seq = buf[K + 22] | (buf[K + 23] << 8);
    }
    dbg_raw_n++;
  }
  if (len > dbg_max_len) dbg_max_len = len;

  // score every candidate rxctl size: does buf+K read like a plausible
  // frame-control byte (version 0, type != reserved)?
  for (int c = 0; c < CAND_N; c++) {
    uint8_t K = cand_off[c];
    if (len < K + 24) continue;
    uint8_t b0 = buf[K];
    if ((b0 & 0x03) == 0 && ((b0 >> 2) & 0x03) != 3) cand_score[c]++;
  }

  // provisional parse at 24 (same as v3.5), for continuity — the winner is
  // whatever offset the scores + hexdump agree on
  uint8_t *f = buf + 24;
  uint16_t flen = len - 24;
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
      Serial.printf("samples: max_len=%u\n", dbg_max_len);
      Serial.print("  candidate off scores (want one big winner):");
      for (uint8_t c = 0; c < CAND_N; c++)
        Serial.printf(" %u=%lu", cand_off[c], cand_score[c]);
      Serial.println();
      for (uint8_t i = 0; i < dbg_raw_n; i++) {
        Serial.printf("  frame%d raw (idx 0-63):\n", i);
        for (uint8_t r = 0; r < 4; r++) {
          Serial.printf("    %02u-%02u: ", r * 16, r * 16 + 15);
          for (uint8_t j = 0; j < 16; j++)
            Serial.printf("%02X ", dbg_raw[i][r * 16 + j]);
          Serial.println();
        }
        const dbg_parse_t *p = &dbg_p12[i];
        Serial.printf("    K=12: fc=%02X %02X dur=%02X %02X a1=%02x:%02x:%02x:%02x:%02x:%02x "
                      "a2=%02x:%02x:%02x:%02x:%02x:%02x a3=%02x:%02x:%02x:%02x:%02x:%02x seq=%04X\n",
                      p->fc0, p->fc1, p->dur0, p->dur1,
                      p->a1[0], p->a1[1], p->a1[2], p->a1[3], p->a1[4], p->a1[5],
                      p->a2[0], p->a2[1], p->a2[2], p->a2[3], p->a2[4], p->a2[5],
                      p->a3[0], p->a3[1], p->a3[2], p->a3[3], p->a3[4], p->a3[5], p->seq);
        p = &dbg_p28[i];
        Serial.printf("    K=28: fc=%02X %02X dur=%02X %02X a1=%02x:%02x:%02x:%02x:%02x:%02x "
                      "a2=%02x:%02x:%02x:%02x:%02x:%02x a3=%02x:%02x:%02x:%02x:%02x:%02x seq=%04X\n",
                      p->fc0, p->fc1, p->dur0, p->dur1,
                      p->a1[0], p->a1[1], p->a1[2], p->a1[3], p->a1[4], p->a1[5],
                      p->a2[0], p->a2[1], p->a2[2], p->a2[3], p->a2[4], p->a2[5],
                      p->a3[0], p->a3[1], p->a3[2], p->a3[3], p->a3[4], p->a3[5], p->seq);
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