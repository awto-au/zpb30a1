#!/usr/bin/env python3
# requirements: pyserial
"""
Fast command fuzzer for the ZPB30A1 stock firmware R (RX) line.

No command set is published anywhere for stock firmware (confirmed by
research, see awto-terminal#79) -- only the telemetry format (9600 8N1,
4-byte BCD voltage+current, see zpb30a1_sniff.py) is known.

Hard/fast mode: sweeps every single byte 0x00-0xFF, and optionally every
2-byte pair, logging telemetry before/after each send so hits can be
mined from the log afterward. Units are expendable (per user) -- no
per-byte confirmation, no slow settle times.
"""

import argparse
import datetime
import itertools
import random
import sys
import time

import serial

BAUD = 9600
FRAME_LEN = 4

# Jitter guard: a single BCD digit (voltage or current) moving by this much
# between before/after reads is treated as normal reading noise, not a hit.
# Observed ~0.01V jitter on a disconnected input during manual testing.
NOISE_TOLERANCE = 0.02

AT_COMMANDS = [
    b"AT\r\n", b"AT+RST\r\n", b"AT?\r\n", b"ATI\r\n", b"AT+GMR\r\n",
    b"AT\r", b"AT\n",
]


def bcd_to_int(byte: int) -> int:
    return (byte >> 4) * 10 + (byte & 0xF)


def read_telemetry_window(ser: serial.Serial, duration_s: float) -> list[str]:
    frames = []
    deadline = time.monotonic() + duration_s
    while time.monotonic() < deadline:
        frame = ser.read(FRAME_LEN)
        if len(frame) == FRAME_LEN:
            b0, b1, b2, b3 = frame
            voltage = bcd_to_int(b0) + bcd_to_int(b1) / 100
            current = bcd_to_int(b2) + bcd_to_int(b3) / 100
            frames.append(f"V={voltage:.2f} I={current:.2f} raw={frame.hex()}")
    return frames


def parse_vi(frame_str: str) -> tuple[float, float] | None:
    # frame_str looks like "V=11.90 I=0.10 raw=11900010"
    try:
        parts = frame_str.split()
        v = float(parts[0].split("=")[1])
        i = float(parts[1].split("=")[1])
        return v, i
    except (IndexError, ValueError):
        return None


def is_real_change(before: str, after: str) -> bool:
    b = parse_vi(before)
    a = parse_vi(after)
    if b is None or a is None:
        return before != after
    dv = abs(a[0] - b[0])
    di = abs(a[1] - b[1])
    return dv > NOISE_TOLERANCE or di > NOISE_TOLERANCE


REPRO_CHECKS = 20


def is_garbage_frame(frame_str: str) -> bool:
    # "V=... I=... raw=xxxxxxxx" -- flag all-0xff / clearly non-BCD raw hex,
    # which showed up as a glitch/reset artifact rather than a real reply.
    try:
        raw = frame_str.split("raw=")[1]
        return raw == "ffffffff"
    except IndexError:
        return False


def check_reproducible(ser: serial.Serial, payload: bytes, settle_s: float, read_s: float,
                        baseline: str) -> tuple[int, int]:
    """Resend payload REPRO_CHECKS times; return (real_changes, garbage_or_silence_count).

    Compares each result against a SINGLE fixed baseline taken once, well
    before this check started -- not a rolling before/after around each
    send. A rolling comparison is fooled by genuine but payload-unrelated
    drift (e.g. voltage settling downward on its own over several
    seconds): every iteration would see "before X, after X-slightly-lower"
    and get wrongly counted as a hit. Comparing against one fixed baseline
    instead asks the right question: does resending this exact payload
    reliably reproduce the exact same effect from the same starting point?
    See awto-terminal#79 -- this bug let a coincidental false positive
    pass an earlier (rolling-comparison) version of this check 20/20.
    """
    hits = 0
    glitches = 0
    for _ in range(REPRO_CHECKS):
        ser.reset_input_buffer()
        ser.write(payload)
        ser.flush()
        time.sleep(settle_s)
        after = read_telemetry_window(ser, read_s)
        after_s = after[-1] if after else "none"
        if not after or is_garbage_frame(after_s):
            glitches += 1
            continue
        if is_real_change(baseline, after_s):
            hits += 1
        time.sleep(0.5)  # let any real payload effect decay before the next probe
    return hits, glitches


def try_payload(ser: serial.Serial, payload: bytes, settle_s: float, read_s: float, log) -> bool:
    ser.reset_input_buffer()
    before = read_telemetry_window(ser, 0.15)
    ser.write(payload)
    ser.flush()
    time.sleep(settle_s)
    after = read_telemetry_window(ser, read_s)

    before_s = before[-1] if before else "none"
    after_s = after[-1] if after else "none"
    candidate = bool(before) and bool(after) and is_real_change(before_s, after_s)
    ts = datetime.datetime.now().astimezone().isoformat(timespec="milliseconds")

    if not candidate:
        log.write(f"{ts} try payload={payload.hex()} before={before_s} after={after_s}\n")
        log.flush()
        return False

    # Candidate hit -- verify it reproduces before trusting it. Take a FRESH
    # baseline here, after a short pause, rather than reusing `before_s`:
    # if voltage is genuinely drifting on its own, `before_s` could itself
    # be mid-drift, and comparing against it would still be fooled. A pause
    # plus fresh read gives the input a chance to settle first.
    time.sleep(1.0)
    settled_baseline = read_telemetry_window(ser, 0.3)
    baseline_s = settled_baseline[-1] if settled_baseline else after_s
    repro_hits, glitches = check_reproducible(ser, payload, settle_s, read_s, baseline_s)
    reproducible = repro_hits >= int(REPRO_CHECKS * 0.9) and glitches == 0
    tag = "HIT" if reproducible else "noise_or_glitch"
    line = (f"{ts} {tag} payload={payload.hex()} before={before_s} after={after_s} "
            f"repro={repro_hits}/{REPRO_CHECKS} glitches={glitches}")
    print(line)
    log.write(line + "\n")
    log.flush()
    return reproducible


def sweep_single_bytes(ser: serial.Serial, settle_s: float, read_s: float, log, stop_on_hit: bool) -> bool:
    print("--- sweeping single bytes 0x00-0xff ---")
    for value in range(256):
        if try_payload(ser, bytes([value]), settle_s, read_s, log) and stop_on_hit:
            print(f"Stopping: hit on single byte 0x{value:02x}")
            return True
    return False


def sweep_single_bytes_crlf(ser: serial.Serial, settle_s: float, read_s: float, log, stop_on_hit: bool) -> bool:
    print("--- sweeping single bytes 0x00-0xff, each CR, LF, and CRLF terminated ---")
    for value in range(256):
        for suffix in (b"\r", b"\n", b"\r\n"):
            payload = bytes([value]) + suffix
            if try_payload(ser, payload, settle_s, read_s, log) and stop_on_hit:
                print(f"Stopping: hit on payload {payload!r}")
                return True
    return False


def sweep_byte_pairs(ser: serial.Serial, settle_s: float, read_s: float, log, stop_on_hit: bool) -> bool:
    print("--- sweeping byte pairs 0x0000-0xffff (this is slow: 65536 combos) ---")
    for a, b in itertools.product(range(256), range(256)):
        if try_payload(ser, bytes([a, b]), settle_s, read_s, log) and stop_on_hit:
            print(f"Stopping: hit on pair {a:02x}{b:02x}")
            return True
    return False


def try_at_commands(ser: serial.Serial, settle_s: float, read_s: float, log, stop_on_hit: bool) -> bool:
    print("--- trying AT command candidates ---")
    for cmd in AT_COMMANDS:
        if try_payload(ser, cmd, settle_s, read_s, log) and stop_on_hit:
            print(f"Stopping: hit on AT command {cmd!r}")
            return True
    return False


def fuzz_random(ser: serial.Serial, settle_s: float, read_s: float, log, stop_on_hit: bool,
                iterations: int, min_len: int, max_len: int) -> bool:
    print(f"--- random fuzzing: {iterations} payloads, length {min_len}-{max_len} ---")
    for _ in range(iterations):
        length = random.randint(min_len, max_len)
        payload = bytes(random.randrange(256) for _ in range(length))
        if random.random() < 0.3:
            payload += random.choice((b"\r", b"\n", b"\r\n"))
        if try_payload(ser, payload, settle_s, read_s, log) and stop_on_hit:
            print(f"Stopping: hit on random payload {payload.hex()}")
            return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Fast command fuzzer for ZPB30A1 R line")
    parser.add_argument("port", nargs="?", default="/dev/ttyUSB0")
    parser.add_argument("--settle", type=float, default=0.05,
                         help="Seconds to wait after sending before reading telemetry")
    parser.add_argument("--read-window", type=float, default=0.2,
                         help="Seconds to capture telemetry after settle")
    parser.add_argument("--stages", default="at,singles,crlf,random",
                         help="Comma-separated stages to run, in order: "
                              "at,singles,crlf,pairs,random")
    parser.add_argument("--random-iterations", type=int, default=2000)
    parser.add_argument("--random-min-len", type=int, default=1)
    parser.add_argument("--random-max-len", type=int, default=8)
    parser.add_argument("--no-stop-on-hit", action="store_true",
                         help="Keep going after a real (non-noise) telemetry change instead of stopping")
    parser.add_argument("--log", default="tmp/logs/zpb30a1_cmd_fuzz.log")
    args = parser.parse_args()

    stop_on_hit = not args.no_stop_on_hit
    stages = [s.strip() for s in args.stages.split(",") if s.strip()]

    print(f"python={sys.executable}")
    print(f"pyserial={serial.__version__}")
    print(f"port={args.port}")
    print(f"stages={stages}")
    print(f"stop_on_hit={stop_on_hit}")
    print(f"log={args.log}")

    with serial.Serial(port=args.port, baudrate=BAUD, timeout=0.1) as ser:
        with open(args.log, "a") as log:
            log.write(f"# session start {datetime.datetime.now().astimezone().isoformat()} "
                       f"port={args.port} stages={stages}\n")
            try:
                for stage in stages:
                    hit = False
                    if stage == "at":
                        hit = try_at_commands(ser, args.settle, args.read_window, log, stop_on_hit)
                    elif stage == "singles":
                        hit = sweep_single_bytes(ser, args.settle, args.read_window, log, stop_on_hit)
                    elif stage == "crlf":
                        hit = sweep_single_bytes_crlf(ser, args.settle, args.read_window, log, stop_on_hit)
                    elif stage == "pairs":
                        hit = sweep_byte_pairs(ser, args.settle, args.read_window, log, stop_on_hit)
                    elif stage == "random":
                        hit = fuzz_random(ser, args.settle, args.read_window, log, stop_on_hit,
                                           args.random_iterations, args.random_min_len, args.random_max_len)
                    else:
                        print(f"unknown stage {stage!r}, skipping")
                        continue
                    if hit and stop_on_hit:
                        break
            except KeyboardInterrupt:
                print("stopped")
    print("Fuzz pass complete. Check log for HIT lines (telemetry changed after a payload, beyond noise tolerance).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
