# ZPB30A1 Stock Serial Protocol (Reverse-Engineered)

Reverse-engineered documentation of the **stock/factory firmware** serial protocol
for the ZPB30A1(P) electronic DC load module (sold under the Zhiyu/ZHIYU brand and
various resellers, STM8S-based). Tested against **firmware v3.4**.

## Why this exists

Every previously published resource on this device (ArduinoHannover/ZPB30A1_Firmware,
herm's fork, MikesModz/ZPB30A1, neonll/ESP32_ZPB30A1_Remote) documents a **clean-room
replacement firmware**, built because the stock STM8S005K6/STM8S105K4 is read-out and
write protected — stock firmware itself has never been dumped or analyzed by any of
those projects.

The only prior attempts to characterize *stock* firmware's serial behavior are:
- [Silicon Chip Australia, March 2023 review](https://www.siliconchip.com.au/Issue/2023/March/ZPB30A1+30V+10A+DC+Load) (Jim Rowe)
- [David Douard's 2016 blog post](https://whatever.sdfa3.org/zpb30a1-electronic-load.html)
- [stylesuxx/discharge-logger](https://github.com/stylesuxx/discharge-logger)

All three claim **115200 baud, 3-byte binary frames**. Empirical testing against a
real unit on **firmware v3.4** disproves this — the real protocol is **9600 baud,
4-byte BCD frames**. Either v3.4 differs from whatever revision those sources tested,
or those claims were never independently verified against real hardware at the byte
level. This repo documents what was actually measured.

## Protocol summary

**Link layer:**
- 9600 baud, 8N1
- Continuous unsolicited stream on the load's **T** (TX) pin — no request/poll needed
- Only transmits while the device is in **Fun1** mode (constant-current load) *and*
  actively running. **Fun2** (battery capacity test mode) is confirmed silent —
  verified by live-switching modes and watching the stream stop/resume, not just
  inferring from documentation.

**Frame: 4 bytes, BCD-encoded, repeating continuously at ~4 Hz, no header/sync/checksum byte observed**

| Byte | Field | Encoding |
|------|-------|----------|
| 0 | Voltage, integer part | BCD |
| 1 | Voltage, fractional part (hundredths) | BCD |
| 2 | Current, integer part | BCD |
| 3 | Current, fractional part (hundredths) | BCD |

```
voltage = BCD(byte0) + BCD(byte1)/100
current = BCD(byte2) + BCD(byte3)/100
```

Example: `11 90 00 10` decodes to **11.90 V, 0.10 A** — verified against the unit's
own front-panel display at time of capture.

## What's been verified, and how

- **Baud rate**: found by sweeping every standard rate (1200–921600) against a live,
  actively-running unit while watching for stable, repeating byte patterns rather
  than noise. 9600 was the only rate producing a stable pattern that matched the
  front-panel display when BCD-decoded.
- **No hidden status/mode bits**: live-monitored the raw frame while sweeping the
  voltage setpoint, current limit, toggling Fun1↔Fun2, and toggling run/stop. Every
  single observed frame decoded as clean, valid BCD in all four bytes — no stray
  flag bits, no non-BCD nibbles, ever. Run/stop and mode state are only visible
  indirectly, through the voltage/current values themselves changing (e.g. voltage
  collapsing when the load engages with nothing connected to its input).
- **Fun2 silence**: confirmed live — switching to Fun2 produced a few transient
  non-BCD garbage bytes during the power-cycle mode-switch itself (reboot noise,
  not real data), then complete silence (no bytes at all) while settled in Fun2.
  Switching back to Fun1 resumed clean telemetry immediately.
- **No command/write capability found**: both the **R** and **L** header pins were
  fuzzed exhaustively as RX candidates — AT commands, the full single-byte range
  (0x00–0xFF), CR/LF-terminated variants, byte pairs, and 3000 random multi-byte
  payloads. No genuine response found on either pin under any payload tried.
  **F** is ruled out separately (constant 50kHz square wave, not a UART signal).
  See `scripts/zpb30a1_cmd_fuzz.py` and the methodology note below.

See `logs/` for raw capture transcripts backing these claims.

## A methodology note on false positives

Fuzzing a floating/disconnected load input is noisy: voltage drifts on its own for
reasons unrelated to any payload sent. Two apparent "hits" during this work turned
out to be exactly that:

- A single byte that appeared to shift the reading, which failed to reproduce at
  all on a clean manual re-test.
- A random multi-byte payload that an early, buggy version of the fuzzer's own
  self-verification reported as **20/20 reproducible** — convincing on its face,
  but it also failed to reproduce under manual re-test. The bug: the verification
  compared each repeat against a rolling "right before this exact send" baseline
  rather than one fixed, settled baseline. If the reading is drifting on its own,
  every repeat sees "before X, after slightly-less-than-X" and gets counted as a
  hit — 20 times in a row — with zero relation to the payload actually sent.

The fuzzer now takes one fixed baseline after a settle period and requires ≥90%
reproducibility against *that* single reference, with zero tolerance for
glitch/garbage frames, before reporting anything as a real hit. If you fuzz other
candidate pins or payloads, be skeptical of any "hit" that isn't checked this way.

## What's still unknown

- **Pin identity**: the 6-pin header (`G, R, T, L, F, Vc`) pin purposes beyond
  G(round)/T(x)/Vc are inferred, not confirmed. **F** is confirmed to carry a
  constant 50kHz square wave (unrelated to UART, likely PWM for something else).
  **L** was tested as an RX candidate (see above) with no result — its actual
  function remains unknown.
- **Logic level**: inferred 3.3V (based on a related open-source project wiring a
  3.3V-logic ESP32 directly to this header with no level shifter), never
  independently measured with a meter/scope on a real unit.
- **Checksum/framing**: no checksum or sync byte observed, but only tested in Fun1
  mode with no DUT connected to the load's input — not verified across the full
  voltage/current range or under fault conditions (overcurrent, overtemperature).

## Repo contents

- `scripts/zpb30a1_sniff.py` — pyserial tool, decodes the live 9600-baud 4-byte BCD
  stream in real time. `--sweep` mode available for baud rediscovery on other units/
  firmware revisions.
- `scripts/zpb30a1_live_monitor.py` — interactive live monitor: shows every frame,
  diffs against the previous frame, tracks every distinct value seen per byte
  position. Used to verify no hidden status bits exist (see above).
- `scripts/zpb30a1_cmd_fuzz.py` — fuzzer for the R (RX) pin: AT commands, single-byte
  sweep, CR/LF-terminated variants, byte pairs, random payloads. No confirmed command
  response found yet — contributions/further testing welcome.
- `logs/` — raw capture transcripts: baud sweep discovery, telemetry samples, a live
  monitor session covering mode/setting changes, and a command-fuzzing session
  transcript (including the corrected, verified-no-hits final sweep).

## Hardware

- Device: ZPB30A1(P) electronic DC load, stock firmware v3.4
- MCU: STM8S105K4 (per Silicon Chip) or STM8S005K6 (per Douard) — sources disagree,
  unresolved
- 6-pin header, unpopulated pads: `G, R, T, L, F, Vc`
- Tested via a generic CH340 USB-serial adapter

## Contributing

If you have a different firmware version, or get the R/L pin command side working,
please open an issue or PR — this is the first public documentation of stock
firmware's protocol and is very likely incomplete.

## License

Public domain / do whatever you want with this. No warranty — this is reverse-engineered
from observed behavior, not vendor documentation.
