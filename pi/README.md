# pi — aggregator + dashboard

What runs on the Pi (the other half of the sensor). One process: an MQTT
subscriber that keeps an in-memory view of who was heard, plus a tiny
Flask HTTP server.

- `app.py` — everything: MQTT attach on `presence/sighting` +
  `presence/online`, dedup window, REST API, dashboard page.
- `Dockerfile` / `requirements.txt` — container build.

Env: `MQTT_HOST` (default localhost), `MQTT_PORT` (1883), `HOME_S` (300 =
"who's home" window), `DEDUP_S` (120), `PORT` (8000).

Run on the Pi (mosquitto already lives in Docker on the same host):

    docker build -t presence-hub pi/
    docker run -d --name presence-hub --restart unless-stopped \
      --network host -e MQTT_HOST=localhost presence-hub

Dashboard: http://<pi>:8000  ·  API: /api/who, /api/stats, /healthz