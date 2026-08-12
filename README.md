# pi-presence-radar

Knowing who's home without asking anyone. Two ESP8266 boards sit in
promiscuous mode and listen for 802.11 probe requests — the packets a
phone broadcasts to find Wi-Fi networks — then post sightings over MQTT
to the Pi. A small web app turns the stream into a "who's home" list.

> intro: one or two lines in your own words (what it is, why you built it).

## How it fits together

```
[phone ~500m away]                       [Raspberry Pi 4B]
        | probe request                         |
        v                                        |
[NodeMCU A (V1)] --MQTT--> [Mosquitto] --> [aggregator] --> [web: who's home]
[NodeMCU B (V3)] --MQTT-->        ^                               |
                                  +---------------- localhost:8000 -+
```

- sniffers: `firmware/` — ESP8266 sketches (one per board, same core)
- hub: `pi/` — aggregator + dashboard (Docker on the Pi)
- docs: `docs/` — wiring, build log
- numbers: `measurements/`

## Hardware

- 2× NodeMCU (ESP8266) — V1 (CP2102) and V3 (CH340)
- Raspberry Pi 4B, 8 GB — Mosquitto + aggregator + dashboard
- (no other parts — the boards sniff passively, powered by USB only)

## Status

- [ ] finalize sniffing firmware (promiscuous receive)
- [ ] flash both NodeMCUs, confirm sightings
- [ ] MQTT sightings -> broker
- [ ] aggregator + who's-home dashboard
- [ ] measurements + photos