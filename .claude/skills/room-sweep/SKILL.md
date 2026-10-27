---
name: room-sweep
description: Sweep a hotel room, Airbnb, or rental for hidden cameras, microphones, item trackers (AirTag/Tile/SmartTag) and suspicious IoT devices using passive Wi-Fi, Bluetooth/BLE and LAN-announcement listening, then walk the user through a physical inspection. Also detects a tracker that keeps showing up at different locations. Use when the user arrives somewhere new, asks "are there cameras in here", "is someone tracking me", or wants to sweep a room.
---

# Room sweep

Runs `travelsec room`, which is **passive**: it reads Wi-Fi beacons, BLE advertisements, and announcements that devices broadcast on the network the user was given. Nothing is sent to other people's devices, so it's appropriate anywhere.

## Steps

1. Ask for (or infer) a short label for the place, e.g. "marriott paris rm 412". The label powers cross-location tracker detection, so encourage using one every time.
2. Run from the repo root:
   ```bash
   python3 -m travelsec --json room --label "<place>"
   ```
   It takes about a minute. If the report notes that the firewall blocks discovery, and the user is connected to the room's Wi-Fi and wants the LAN part to be complete, they can run it themselves in another terminal (it needs sudo): `sudo scripts/with-discovery.sh room --label "<place>"`. Explain that it opens inbound UDP from the local subnet only for the duration of the scan.
3. If Bluetooth is off, ask the user to turn it on (`bluetoothctl power on`) rather than doing it silently.

## How to interpret

Order the answer: **likely in this room → worth physically checking → background noise.**

- **Signal strength is the location clue.** Wi-Fi signal ≥ 75 or BLE RSSI > −65 dBm usually means the same room or the next one. Weak signals are probably other rooms or the street. Say this explicitly; most hits in a hotel are neighbors' devices.
- **Camera-style SSIDs / camera-maker vendors / RTSP or ONVIF on the LAN (high):** the strongest signals of a camera. Use the vendor and signal to suggest where to look.
- **IoT setup hotspots / Espressif-Tuya-type chips nearby (medium):** cheap smart plugs, cameras, and sensors all use these. Worth locating if strong.
- **Find My separated (high):** an Apple accessory away from its owner. One sighting in a hotel is often a neighbor's luggage tag. A **"seen at N of your locations"** finding is the real stalking signal. Advise using the phone's built-in unknown-tracker scan (iOS: Find My → Identify Found Item; Android: Settings → Safety & emergency → Unknown tracker alerts → Scan now) to make it beep, and contacting police if it's on their belongings.
- **Tile / SmartTag (medium):** same logic; persistence across locations is what matters.
- **Randomized MACs / random BLE addresses** are phones and laptops protecting their privacy, not threats.
- Smart TVs, Chromecasts, and speakers on a hotel network are normal. Mention that TVs can have mics and cameras: unplug them or cover them if the user cares.

Then **always** walk through `data.physical_checklist`, putting first the items that match the RF hits (e.g. a strong unknown Espressif device → check chargers, clocks, and smoke detectors first). RF sweeps miss cameras that record to an SD card without Wi-Fi, so the physical check isn't optional.

If something looks like a camera in a private area (bedroom, bathroom): tell them to document it, avoid tampering beyond covering it, and report to the platform (Airbnb, etc.) and local police. Most platforms ban indoor cameras outright.
