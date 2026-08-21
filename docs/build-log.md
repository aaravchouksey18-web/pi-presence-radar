# build log

## The plan
Repo started. The MQTT backbone was already live on the Pi when this began
(mosquitto in Docker, port 1883 — the same broker the other Pi projects
share). Boards in the drawer: NodeMCU V1 (CP2102) and V3 (CH340), both
ESP8266. Plan for this project: run them in promiscuous mode, sniff
probe-request frames, publish MAC sightings to the broker, then aggregate
on the Pi and render "who's home".

Tracker: MAC sightings over MQTT, a small Flask app polling the aggregator.

## The build

### The promiscuous saga: "this radio cannot hear anything" (it could)
Goal: passive channel-6 sniffer. Baseline was trivial — the board joined
the home network, MQTT-connected, DHCP, the lot. Turning on promiscuous RX
is where the day went sideways.

**The symptom:** every 15-second sniff session reported ZERO probe requests
and ZERO beacons. On a live channel that is physically impossible — the
router sits a few meters away (Pi sees it at -49 dBm). Meanwhile the
session frame counts (400-800) and weird control-frame storms said the
radio was clearly receiving SOMETHING. Multiple wrong theories followed:
phy wouldn't lock the channel after a prior association (v3.2, maybe real,
moot); sniff-first-at-boot cycler (v3.3); long-frame FCS drops; broken
antenna. The one tool that kept paying off was the histogram: count
everything the callback hands you, bucket by type/subtype, print at session
end. From there, a raw-frame sampler ("print the first frames' bytes")
broke it open.

The samples were the tell. Every frame arrived as a uniform 128-byte block
starting 0xAA/0xC9 with a "source MAC" of 06:00:80:00:00:00 — not a real
MAC, that's the Espressif rxctl receive-control header (RSSI, rate,
channel...). The SDK prepends it to every promiscuous frame: `wifi_pkt_
rx_ctrl_t` on this core. We were parsing the HEADER as the frame. Every
"0 probes" conclusion going back versions read garbage.

Guessing the rxctl size once already misled (tried +24: headers read
"0D E7 02 AA..." and histograms hallucinated 508 deauths). So: firmware
that teaches you the offset — score 8-12 candidate offsets by how often the
byte there looks like a valid frame-control (version 0, type != reserved),
and dump raw bytes with index labels. Winners at 22 and 28 (6 apart,
suspicious), and offset 12 hadn't even been in the candidate list — yet the
dump showed a full beacon sitting at +12: FC 0x80 00, broadcast A1, A2=A3
= <home-bssid> (the router), timestamp, beacon interval 0x64,
and the SSID tag literally spelling out the home network name. Offset 12
then scored a valid frame-control byte on 1123/1123 frames. **rxctl is
12 bytes.**

v3.8 with the real parser: 397-415 beacons/session, probe_requests coming
in, and the first captured probe MACs (a couple of Apple-OUIs — real
devices, anonymized in this log). The radio had been fine the whole time.

Lesson: when hardware "definitely can't hear anything," print the raw
bytes; and pin API knowledge to the exact SDK/core version — the
canonical ESP8266 sniffer tutorials assume a raw frame, some SDKs wrap it.

### The brownout
First v3.8 flash: esptool wrote 100% then failed its MD5Sum check with a
garbled serial reply. The board went silent for 5.5 minutes — broker logs
showed a clockwork 45-second reconnect cycle simply stop. Same story from
the power side: marginal USB power on the V1 dips under load (100% flash
write draws peak current). Re-flash (second attempt) verified clean
"Hash of data verified" and the cycle resumed.

### The RTC queue was a dead end
Sightings were captured but never reached the broker. publish_queue
printed nothing despite the RTC queue being committed — because every boot
logged `rst cause:1` = POWER-ON reset. The board is power-cycling each
cycle (ESP.restart() gives a soft reset, cause 6, but we got cause 1), and
a cold boot wipes RTC memory. The RTC queue — designed for at-least-once
delivery across reboots — couldn't survive the very thing it was built
for. Since the sniff phase and the report phase run in the same boot, the
seen table is still in RAM at publish time. v3.9 drops RTC entirely and
publishes straight from RAM. Simplest layer that survives this board's
power behavior.

### Working as designed
End-to-end: sniff-at-boot on ch6, probe requests → SSID parse → JSON →
MQTT `presence/sighting`. Live broker trace, one cycle:

    presence/sighting {"board":"a","mac":"aa:bb:cc:00:00:01","ssid":"neighbor-ssid"}
    presence/sighting {"board":"a","mac":"aa:bb:cc:00:00:02"}
    presence/sighting {"board":"a","mac":"aa:bb:cc:00:00:03","ssid":"home-ssid"}
    presence/sighting {"board":"a","mac":"aa:bb:cc:00:00:04"}
    presence/sighting {"board":"a","mac":"aa:bb:cc:00:00:05"}

(MACs and SSIDs anonymized — the shape is real, the values aren't.)
Randomized-MAC probes (aa:bb:cc:00:00:02/04 patterns — locally
administered bit set) are phones scanning generically; aa:bb:cc:00:00:03
probing home-ssid is a device knowingly hunting its home network — the
reconnect pattern you see when someone toggles WiFi. That'll be the
phone-home demo: toggle phone WiFi next to the board, watch the MAC land.
(Do NOT toggle your Mac's WiFi during this — it's the ssh link.)

### Measured
- beacon rate on ch6: ~26/s (415 in a 15s session)
- probe requests/session: 4-11 (idle house), all one or two real devices
- cycle: ~15s sniff + ~30s report + reboot ≈ 45-46s
- sighting latency: same-boot (seconds after report phase connects)
- Pi sees the home network at -49 dBm; home 2.4GHz BSSID and a second AP
  on ch6 (hidden SSID) both anonymized in this log

### Open
- V1 board power is marginal: one corrupted flash already, cause unknown
  beyond brownout suspicion. Candidate fix for a field build: better USB
  source, or a NodeMCU V3 swap, or brownout-detector handling (careful —
  that's what caught the corrupt flash).
- Board "a" is the V1 on the bench. V3 (board "b") still unflashed.
- Second sensor = second venue; aggregator dedup is by (mac, board, time).

### Aggregator + dashboard (same day)
The Pi gets a process that subscribes to presence/sighting and
presence/online, keeps an in-memory view (dedup: any report of an already-
known mac refreshes its last_seen — that refresh IS the "still home"
signal), and serves the data over HTTP. One python file, flask + paho-mqtt,
in Docker like the broker: `presence-hub`, published port 8000, MQTT via
mosquitto's docker-bridge IP.

    GET /api/who    devices heard within the HOME_S window (default 300s)
    GET /api/stats  totals + per-board liveness
    GET /           dashboard page, polls the API every 5s

Live ~1 minute after first boot: two devices in /api/who, one carrying the
SSID it probed for, board "a" shown alive via its retained
online message. Full chain now: NodeMCU sniffer -> MQTT -> aggregator ->
dashboard.

(The dashboard's first container used --network host and silently failed
from the LAN: the Pi's host firewall drops incoming connections to bare
host binds, while docker-published ports get their own accept rule. Fix:
publish 8000 like mosquitto does, and talk MQTT to mosquitto's bridge IP —
container-to-container, no firewall in the path. Documented in pi/README.md.)

### Closeout
Still to do: V3 as a second sensor (board "b"), photo of the rig, README
intro in my own words, and the phone-home toggle demo writeup with numbers.