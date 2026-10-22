#!/usr/bin/env python3
# requirements: pyserial
"""
UART sniffer/decoder for the ZPB30A1(P) electronic load, stock firmware v3.4.

Published sources (Silicon Chip Australia Mar 2023, David Douard 2016
teardown, stylesuxx/discharge-logger) all claim 115200 baud, 3-byte binary
voltage+status frames -- but empirical capture against this unit (firmware
v3.4) disproves that: a baud sweep showing stable, scaled byte patterns
from 1200-76800 baud, cross-checked against the front-panel display
(11.90V / 0.1A), confirmed the real rate is 9600 baud with 4-byte BCD
frames, not 115200/3-byte binary. See awto-terminal#79.

Serial only transmits while the load is in "Fun1" (constant-current load)
mode and actively running -- "Fun2" (battery capacity test) mode is
silent (this part matches all three published sources).

Frame (4 bytes, BCD-encoded, repeating continuously):
  byte0 = voltage integer part (BCD, tens+ones digit)
  byte1 = voltage fractional part (BCD, tenths+hundredths digit)
  byte2 = current integer part (BCD)
  byte3 = current fractional part (BCD)
  voltage = BCD(byte0) + BCD(byte1)/100; current = BCD(byte2) + BCD(byte3)/100

This tool never writes to the port. Default mode decodes frames assuming
the device is already in Fun1 and running; --sweep falls back to the
baud-sweep raw logger for initial discovery on a different unit/firmware.
"""

import argparse
import datetime
import sys
import time

import serial

DEFAULT_BAUD_SWEEP = [
    1200, 2400, 4800, 9600, 14400, 19200, 28800, 38400,
    56000, 57600, 76800, 115200, 128000, 153600, 230400,
    250000, 256000, 460800, 500000, 921600,
]

ZPB30A1_BAUD = 9600
FRAME_LEN = 4


def bcd_to_int(byte: int) -> int:
    return (byte >> 4) * 10 + (byte & 0xF)


def bytes_preview(data: bytes) -> str:
    hex_part = data.hex(" ")
    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return f"hex={hex_part} ascii={ascii_part!r}"


def sniff_fixed_baud(port: str, baud: int, duration_s: float, log) -> int:
    total = 0
    deadline = time.monotonic() + duration_s
    with serial.Serial(port=port, baudrate=baud, timeout=0.2) as ser:
        ser.reset_input_buffer()
        while time.monotonic() < deadline:
            data = ser.read(256)
            if data:
                ts = datetime.datetime.now().astimezone().isoformat(timespec="milliseconds")
                line = f"{ts} baud={baud} len={len(data)} {bytes_preview(data)}"
                print(line)
                log.write(line + "\n")
                log.flush()
                total += len(data)
    return total


def decode_frames(port: str, log) -> None:
    with serial.Serial(port=port, baudrate=ZPB30A1_BAUD, timeout=1.0) as ser:
        ser.reset_input_buffer()
        print(f"listening at {ZPB30A1_BAUD} 8N1, decoding {FRAME_LEN}-byte BCD frames (Ctrl-C to stop)")
        while True:
            frame = ser.read(FRAME_LEN)
            ts = datetime.datetime.now().astimezone().isoformat(timespec="milliseconds")
            if len(frame) != FRAME_LEN:
                line = f"{ts} short_read len={len(frame)} {bytes_preview(frame)}"
                print(line)
                log.write(line + "\n")
                log.flush()
                continue
            b0, b1, b2, b3 = frame
            voltage = bcd_to_int(b0) + bcd_to_int(b1) / 100
            current = bcd_to_int(b2) + bcd_to_int(b3) / 100
            line = (f"{ts} raw={bytes_preview(frame)} "
                    f"voltage={voltage:.2f}V current={current:.2f}A")
            print(line)
            log.write(line + "\n")
            log.flush()


def main() -> int:
    parser = argparse.ArgumentParser(description="UART sniffer/decoder for ZPB30A1 stock firmware")
    parser.add_argument("port", nargs="?", default="/dev/ttyUSB0")
    parser.add_argument("--sweep", action="store_true",
                         help="Raw baud-rate sweep instead of fixed 115200 frame decode")
    parser.add_argument("--baud", type=int, default=None,
                         help="With --sweep: fixed baud rate; omit to sweep DEFAULT_BAUD_SWEEP")
    parser.add_argument("--dwell", type=float, default=3.0,
                         help="With --sweep: seconds to listen per baud rate")
    parser.add_argument("--log", default="tmp/logs/zpb30a1_sniff.log")
    args = parser.parse_args()

    print(f"python={sys.executable}")
    print(f"pyserial={serial.__version__}")
    print(f"port={args.port}")
    print(f"log={args.log}")

    with open(args.log, "a") as log:
        log.write(f"# session start {datetime.datetime.now().astimezone().isoformat()} port={args.port}\n")
        try:
            if args.sweep:
                bauds = [args.baud] if args.baud else DEFAULT_BAUD_SWEEP
                print(f"bauds={bauds}")
                print("Operate the load's front panel now (PC-link / remote / discharge start).")
                while True:
                    for baud in bauds:
                        print(f"--- listening at {baud} baud for {args.dwell}s ---")
                        total = sniff_fixed_baud(args.port, baud, args.dwell, log)
                        if total:
                            print(f"  got {total} bytes at {baud} baud")
                    if args.baud is not None:
                        break
            else:
                print("Device must be in Fun1 mode and actively running a CC load.")
                decode_frames(args.port, log)
        except KeyboardInterrupt:
            print("stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
