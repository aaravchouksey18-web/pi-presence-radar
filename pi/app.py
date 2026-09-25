#!/usr/bin/env python3
"""presence-vigil aggregator + "who's home" dashboard.

Listens on the shared MQTT broker for presence/sighting and
presence/online, keeps a small dedup'd in-memory view of who was heard
recently, and serves it over HTTP:

  /           - the dashboard (polls the API every few seconds)
  /api/who    - devices currently "home" (seen within HOME_S seconds)
  /api/stats  - counters + board liveness
  /healthz    - docker healthcheck

Everything is in RAM on purpose: this is a home presence board, not a
cash register. Rebuild/restart the container and you start a fresh day.

Environment: MQTT_HOST, MQTT_PORT, HOME_S, DEDUP_S (defaults below).
"""

import json
import os
import threading
import time

import paho.mqtt.client as mqtt
from flask import Flask, jsonify, render_template_string

MQTT_HOST = os.environ.get("MQTT_HOST", "localhost")
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
HOME_S    = int(os.environ.get("HOME_S", "300"))    # "who's home" window (s)
DEDUP_S   = int(os.environ.get("DEDUP_S", "120"))   # merge re-reports within (s)
ONLINE_S  = int(os.environ.get("ONLINE_S", "150"))  # board proof-of-life window (s)

_lock = threading.Lock()
devices = {}   # mac -> {mac, first_seen, last_seen, ssid, boards:{board:ts}}
boards = {}    # board -> {last_proof, last_lwt, online_seen}

STARTED = time.time()


def _now():
    return time.time()


def record_sighting(board, mac, ssid):
    """Merge a sighting. Same mac re-reported within DEDUP_S (or any later
    cycle) refreshes its last_seen — that IS the "still home" signal."""
    now = _now()
    with _lock:
        d = devices.get(mac)
        if d is None:
            d = {"mac": mac, "first_seen": now, "last_seen": now,
                 "ssid": ssid, "boards": {}}
            devices[mac] = d
        else:
            d["last_seen"] = now
            if ssid and not d["ssid"]:
                d["ssid"] = ssid
        d["boards"][board] = now
        # hearing from a board is proof it is alive
        b = boards.setdefault(board, {})
        b["last_proof"] = now
        if not b.get("online_seen"):
            b["online_seen"] = now


def record_online(board, online):
    now = _now()
    with _lock:
        b = boards.setdefault(board, {})
        if online:
            b["last_online"] = now
        else:
            b["last_lwt"] = now   # LWT: board dropped (timeout / crash)


def board_alive(board):
    """True if the board has proven itself recently: retained online msg,
    a fresh sighting, or an LWT within ONLINE_S."""
    now = _now()
    b = boards.get(board) or {}
    return now - b.get("last_online", 0) < ONLINE_S \
        or now - b.get("last_proof", 0) < ONLINE_S


# --- MQTT ------------------------------------------------------------------

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        client.subscribe("presence/sighting")
        client.subscribe("presence/online")
        print(f"[mqtt] connected to {MQTT_HOST}:{MQTT_PORT}, listening", flush=True)
    else:
        print(f"[mqtt] connect failed rc={rc}", flush=True)


def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
    except (ValueError, UnicodeDecodeError):
        return
    board = payload.get("board")
    if not board:
        return
    if msg.topic == "presence/sighting":
        mac = payload.get("mac")
        if mac:
            record_sighting(board, mac, payload.get("ssid", ""))
    elif msg.topic == "presence/online":
        record_online(board, bool(payload.get("online")))


mq = mqtt.Client()
mq.on_connect = on_connect
mq.on_message = on_message


def mqtt_loop():
    while True:
        try:
            mq.connect(MQTT_HOST, MQTT_PORT, keepalive=30)
            mq.loop_forever()
        except Exception as e:                       # broker restart etc.
            print(f"[mqtt] {e}; retrying in 5s", flush=True)
            time.sleep(5)


threading.Thread(target=mqtt_loop, daemon=True).start()

# --- HTTP -------------------------------------------------------------------

app = Flask(__name__)


@app.get("/api/who")
def api_who():
    cutoff = _now() - HOME_S
    with _lock:
        home = [d for d in devices.values() if d["last_seen"] >= cutoff]
        home.sort(key=lambda d: d["last_seen"], reverse=True)
        data = []
        for d in home:
            data.append({
                "mac": d["mac"],
                "ssid": d["ssid"],
                "age_s": int(_now() - d["last_seen"]),
                "boards": sorted(d["boards"]),
                "heard_by": len(d["boards"]),
            })
        return jsonify({"home_s": HOME_S, "devices": data, "now": int(_now())})


@app.get("/api/stats")
def api_stats():
    with _lock:
        total = len(devices)
        home = sum(1 for d in devices.values() if d["last_seen"] >= _now() - HOME_S)
        sightings = sum(len(d["boards"]) for d in devices.values())
        bstats = []
        for bid in sorted(boards):
            bstats.append({"board": bid, "alive": board_alive(bid)})
        return jsonify({
            "uptime_s": int(_now() - STARTED),
            "devices_total": total,
            "devices_home": home,
            "device_board_pairs": sightings,   # distinct (device, board) pairs
            "boards": bstats,
        })


@app.get("/healthz")
def healthz():
    return "ok", 200


PAGE = r"""<!doctype html>
<html><head><meta charset="utf-8">
<title>presence-vigil — who's home</title>
<style>
  :root { --bg:#0f1419; --card:#1a222b; --line:#2a3441; --tx:#e6edf3;
          --dim:#7d8b99; --ok:#3fb950; --dead:#f85149; }
  * { box-sizing:border-box; }
  body { background:var(--bg); color:var(--tx); font:14px/1.5 ui-monospace,
         SFMono-Regular, Menlo, monospace; margin:0; padding:24px; }
  h1 { font-size:18px; margin:0 0 4px; }
  .sub { color:var(--dim); margin-bottom:20px; }
  .strip { display:flex; gap:8px; margin-bottom:20px; flex-wrap:wrap; }
  .chip { border:1px solid var(--line); border-radius:6px; padding:6px 10px;
          background:var(--card); }
  .chip .dot { display:inline-block; width:8px; height:8px; border-radius:50%;
          margin-right:6px; }
  .ok .dot { background:var(--ok); } .dead .dot { background:var(--dead); }
  .cards { display:grid; grid-template-columns:repeat(auto-fill,minmax(240px,1fr));
           gap:12px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:8px;
          padding:12px 14px; }
  .card .mac { font-weight:bold; }
  .card .ssid { color:var(--ok); font-size:12px; }
  .card .meta { color:var(--dim); font-size:12px; margin-top:6px; }
  .empty { color:var(--dim); }
</style></head>
<body>
  <h1>who&rsquo;s home</h1>
  <div class="sub">presence-vigil · ch6 probe sniffer · <span id="clock">–</span></div>
  <div class="strip" id="strip"></div>
  <div class="cards" id="cards"></div>
<script>
async function tick() {
  const who = await (await fetch('/api/who')).json();
  const stats = await (await fetch('/api/stats')).json();
  document.getElementById('clock').textContent =
    new Date(who.now * 1000).toLocaleTimeString();
  const strip = document.getElementById('strip');
  strip.innerHTML = '';
  stats.boards.forEach(b => {
    const el = document.createElement('div');
    el.className = 'chip ' + (b.alive ? 'ok' : 'dead');
    el.innerHTML = `<span class="dot"></span>board ${b.board}${b.alive ? '' : ' (gone)'}`;
    strip.appendChild(el);
  });
  const cards = document.getElementById('cards');
  cards.innerHTML = '';
  if (!who.devices.length) {
    cards.innerHTML = '<div class="empty">no devices heard in the last ' +
      who.home_s + 's &mdash; toggle a phone&rsquo;s wifi near the board.</div>';
    return;
  }
  who.devices.forEach(d => {
    const el = document.createElement('div');
    el.className = 'card';
    const ago = d.age_s < 90 ? '<span style="color:var(--ok)">now</span>'
              : (Math.round(d.age_s / 60) + 'm ago');
    el.innerHTML = `<div class="mac">${d.mac}</div>
      <div class="ssid">${d.ssid ? '❯ ' + d.ssid : ''}</div>
      <div class="meta">seen ${ago} · board ${d.boards.join(', ')}</div>`;
    cards.appendChild(el);
  });
}
tick();
setInterval(tick, 5000);
</script></body></html>"""


@app.get("/")
def index():
    return render_template_string(PAGE)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")), threaded=True)