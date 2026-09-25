# measurements

Session figures from the live rig (board "a", channel 6, idle house):

- beacon rate: ~26/s (415 in a 15 s session)
- probe requests per 15 s session: 4-11, normally one or two real devices
- station background: home router heard at -49 dBm
- cycle: ~15 s sniff + ~30 s report + reboot ≈ 45-46 s
- sighting latency: same-boot (seconds after the report phase connects)

Dual-board demo session (boards "a" and "b" together):

- distinct devices over the session: 13
- device/sensor pairs: 20
- devices caught by both sniffers: several (`heard_by:2` in /api/who)

These are the numbers the build log and the dashboard actually showed —
nothing here is rounded up or projected.