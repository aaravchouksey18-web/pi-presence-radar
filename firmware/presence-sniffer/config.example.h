// config.example.h — copy to config.h and fill in. config.h is gitignored
// (it holds your Wi-Fi password, don't commit it).
#pragma once

#define WIFI_SSID   "your-ssid"
#define WIFI_PASS   "your-password"

#define MQTT_HOST   "<pi-ip>"   // Pi on the LAN
#define MQTT_PORT   1883

#define SNIFF_CHANNEL 6              // your router's channel (improves catch rate)

#define BOARD_ID    "a"              // "a" / "b" — one per NodeMCU

// v3 cycle: promiscuous capture permanently kills the ESP8266 station's TX
// (proven in the build log), so the board boots, phones home, sniffs, and
// reboots. Sightings queue in RTC memory across the reboot.
#define SNIFF_SESSION_MS 15000       // radio in capture mode per cycle
#define IDLE_MS 6000                 // clean-radio window after boot, pre-sniff