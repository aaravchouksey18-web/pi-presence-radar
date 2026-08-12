# build log

## The plan
Repo started. The MQTT backbone was already live on the Pi when this began
(mosquitto in Docker, port 1883 — the same broker the other Pi projects
share). Boards in the drawer: NodeMCU V1 (CP2102) and V3 (CH340), both
ESP8266. Plan for this project: run them in promiscuous mode, sniff
probe-request frames, publish MAC sightings to the broker, then aggregate
on the Pi and render "who's home".

Tracker: MAC sightings over MQTT, a small Flask app polling the aggregator.

## The build — tbd