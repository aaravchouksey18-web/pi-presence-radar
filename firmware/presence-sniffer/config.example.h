// config.example.h — copy to config.h and fill in. config.h is gitignored
// (it holds your Wi-Fi password, don't commit it).
#pragma once

#define WIFI_SSID   "your-ssid"
#define WIFI_PASS   "your-password"

#define MQTT_HOST   "<pi-ip>"   // Pi on the LAN
#define MQTT_PORT   1883

#define SNIFF_CHANNEL 6              // your router's channel (improves catch rate)

#define BOARD_ID    "a"              // "a" / "b" — one per NodeMCU

// v3 cycle: sniff FIRST from a cold unassociated radio at boot (the only
// state where ESP8266 promiscuous actually locks the channel), then
// associate + report + reboot. Sightings queue in RTC memory across reboots.
#define SNIFF_SESSION_MS 15000       // radio in capture mode at boot
#define PH_HOME_MS 30000             // max time associating + reporting