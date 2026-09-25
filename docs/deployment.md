# House deployment plan

Target: a dozen standalone sniffers spread across the house, one per
station, each running off an 18650 cell with a charge circuit — so a node
survives mains dropout and can be relocated without rewiring. The firmware
already suits this: every board boots, connects once, sniffs a window,
publishes, and recycles. It loses power mid-cycle and simply boots again
on the next decent supply. A battery node is the same board as boards "a"
and "b" — minus the wall adapter.

## Node hardware (per station)

- NodeMCU (ESP8266), flashed with the same sketch as boards "a" and "b"
- one 18650 cell + charge module (micro-USB in, same 5 V rail the Pi USB
  used to supply), feeding the board through the module's output stage —
  drop-in, no soldered power stage required
- power wiring is hand-done and short; a purpose-made charge/no-charge
  board is a listed upgrade, not a blocker

Power budget is not measured end-to-end yet (no cells in hand). The board
cycle is short radio bursts between idle windows, so even a conservative
2500 mAh cell should carry a station through an overnight mains outage.
Endurance gets a measurement entry once the first cell arrives.

## Stations

Rooms picked for foot traffic and coverage spread; the map below is the
target, tuned after the first cells come in:

| station | job |
|---|---|
| kitchen | highest pass-by rate, entry-adjacent |
| living room | daytime occupancy |
| main bedroom | evening and night presence |
| second bedroom | spare, guest presence |
| hallway | transit choke point |
| study | work-hours occupancy |
| dining | meal-time presence |
| landing / stairs | second-floor crossing |
| balcony side | far edge of the house |
| utility | appliance-corner coverage |
| garage side | entry coverage from outside |
| spare station | hot-swap / moving node (carried around) |

## Channels

The radio sniffs one 2.4 GHz channel at a time; a station parked on the
wrong channel misses the action. Plan: map the router channels the house
actually sees, pick the dominant ones, and pin each station to the busiest
channel it can hear — a per-station channel constant (today everything is
on channel 6). Cross-channel switching inside one sniff window is noted
as a firmware idea, not a promise.

## MQTT and the aggregator

Every station speaks the same contract today:

```
presence/sighting  {"board":"<id>","mac":"…","ssid":"…"}
presence/online    {"board":"<id>","online":true|false}
```

The aggregator keys on (mac, board, time) and dedups by heard_by, so a
twelfth board needs zero aggregator changes — the two-board rig already
proved the multi-board path (device/sensor pairs today: 20).

## Provisioning a new station

1. set `BOARD_ID` to the station's id in `config.h` (wifi creds stay
   gitignored, per board)
2. `arduino-cli compile --fqbn esp8266:esp8266:nodemcuv2 .`
3. `arduino-cli upload -p /dev/ttyUSB0 --fqbn esp8266:esp8266:nodemcuv2 .`
4. power it where the station lives — the retained `presence/online`
   message is the liveness check, first report within one boot cycle

## Status

- live today: board "a" on its own power cable, board "b" on the Pi USB
- planned: twelve 18650-backed stations, one per room in the map above

The build log is the record; this page is the plan. Cells are not yet
purchased, channels are not yet split per station, and the station map is
the target — not what is running right now.