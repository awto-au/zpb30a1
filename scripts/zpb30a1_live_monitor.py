#!/usr/bin/env python3
# requirements: pyserial
"""
Live monitor for the ZPB30A1 stock UART (9600 8N1, 4-byte BCD frames --
see zpb30a1_sniff.py / awto-terminal#79, and the public zpb30a1 repo for
the full protocol writeup).

Prints a line every time the raw frame changes at all -- no noise
filtering, no threshold. Every byte in every frame observed so far has
always been valid BCD digits for voltage/current -- no hidden status or
mode bits have ever been found, confirmed across voltage sweeps, current
sweeps, Fun1/Fun2 mode switches, and run/stop toggles. On exit (Ctrl-C),
prints a summary of every distinct value seen at each byte position, and
flags plainly if any non-BCD byte was ever seen (which would mean the
"no hidden bits" finding doesn't hold for your unit/firmware).

Read-only -- never writes to the port.
"""

import argparse
import datetime
import sys
from collections import defaultdict

import serial

BAUD = 9600
FRAME_LEN = 4


def bcd_to_int(byte: int) -> int:
    return (byte >> 4) * 10 + (byte & 0xF)


def is_valid_bcd(byte: int) -> bool:
    return (byte >> 4) <= 9 and (byte & 0xF) <= 9


def main() -> int:
    parser = argparse.ArgumentParser(description="Live monitor for ZPB30A1 UART")
    parser.add_argument("port", nargs="?", default="/dev/ttyUSB0")
    parser.add_argument("--log", default="tmp/logs/zpb30a1_live_monitor.log")
    args = parser.parse_args()

    print(f"python={sys.executable}")
    print(f"pyserial={serial.__version__}")
    print(f"port={args.port}")
    print(f"log={args.log}")
    print("Watching for voltage/current changes. Change settings on the front panel now.")
    print()

    seen_values: dict[int, set[int]] = defaultdict(set)
    prev_frame = None

    with serial.Serial(port=args.port, baudrate=BAUD, timeout=1.0) as ser:
        ser.reset_input_buffer()
        with open(args.log, "a") as log:
            log.write(f"# session start {datetime.datetime.now().astimezone().isoformat()} port={args.port}\n")
            try:
                while True:
                    frame = ser.read(FRAME_LEN)
                    if len(frame) != FRAME_LEN:
                        continue
                    for i, b in enumerate(frame):
                        seen_values[i].add(b)

                    if frame == prev_frame:
                        continue

                    b0, b1, b2, b3 = frame
                    voltage = bcd_to_int(b0) + bcd_to_int(b1) / 100
                    current = bcd_to_int(b2) + bcd_to_int(b3) / 100
                    non_bcd = [i for i, b in enumerate(frame) if not is_valid_bcd(b)]

                    ts = datetime.datetime.now().astimezone().isoformat(timespec="milliseconds")
                    warn = f" UNEXPECTED non-BCD byte(s) at position {non_bcd}!" if non_bcd else ""
                    line = f"{ts} V={voltage:.2f} I={current:.2f} raw={frame.hex(' ')}{warn}"
                    print(line)
                    log.write(line + "\n")
                    log.flush()

                    prev_frame = frame
            except KeyboardInterrupt:
                print("\nstopped.")
                any_non_bcd = False
                for i in range(FRAME_LEN):
                    vals = sorted(seen_values[i])
                    non_bcd_vals = [v for v in vals if not is_valid_bcd(v)]
                    if non_bcd_vals:
                        any_non_bcd = True
                        print(f"  byte{i}: {len(vals)} distinct values, "
                              f"{len(non_bcd_vals)} were NOT valid BCD: {[hex(v) for v in non_bcd_vals]}")
                    else:
                        print(f"  byte{i}: {len(vals)} distinct values, all valid BCD digit pairs")
                if any_non_bcd:
                    print("Some bytes were not valid BCD -- the pure voltage/current model may not "
                          "fully explain this unit's stream. Check the log for details.")
                else:
                    print("Every byte, every value seen this session was valid BCD. "
                          "No hidden status/mode bits found.")
                log.write(f"# every_byte_valid_bcd={not any_non_bcd}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
