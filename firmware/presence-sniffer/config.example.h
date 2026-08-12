// config.example.h — copy to config.h and fill in. config.h is gitignored
// (it holds your Wi-Fi password, don't commit it).
#pragma once

#define WIFI_SSID   "your-ssid"
#define WIFI_PASS   "your-password"

#define MQTT_HOST   "<pi-ip>"   // Pi on the LAN
#define MQTT_PORT   1883

#define SNIFF_CHANNEL 6              // your router's channel (improves catch rate)

#define BOARD_ID    "a"              // "a" / "b" — one per NodeMCU

#define PUBLISH_GAP_MS 10000         // min gap between sightings of same MAC