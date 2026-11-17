#!/usr/bin/env python3
"""Post-build gate: app size headroom and sdkconfig invariants for one board.

Usage: check_build.py --build-dir D --board {t-eth-elite,waveshare-s3-eth,generic-s3-wifi}
Exit 1 if any check fails.
"""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAX_FRACTION = 0.92

# Derived from sdkconfig.defaults / sdkconfig.board.* / main/Kconfig.projbuild.
BOARDS = {
    "t-eth-elite": {
        "csv": "partitions.csv",
        "select": "CONFIG_ADBLOCK_BOARD_T_ETH_ELITE",
        "flash": "CONFIG_ESPTOOLPY_FLASHSIZE_16MB",
    },
    "waveshare-s3-eth": {
        "csv": "partitions.csv",
        "select": "CONFIG_ADBLOCK_BOARD_WAVESHARE_S3_ETH",
        "flash": "CONFIG_ESPTOOLPY_FLASHSIZE_16MB",
    },
    "generic-s3-wifi": {
        "csv": "partitions_wifi.csv",
        "select": "CONFIG_ADBLOCK_BOARD_GENERIC_S3_WIFI",
        "flash": "CONFIG_ESPTOOLPY_FLASHSIZE_8MB",
    },
}
COMMON_REQUIRED = [
    "CONFIG_IDF_TARGET_ESP32S3",
    "CONFIG_SECURE_SIGNED_APPS_NO_SECURE_BOOT",
    "CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE",
    "CONFIG_MBEDTLS_ECDSA_DETERMINISTIC",
]
SEEDS = ["CONFIG_ADBLOCK_WIFI_SSID", "CONFIG_ADBLOCK_WIFI_PASSWORD"]

results = []


def check(ok, msg):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + msg)


def parse_size(tok):
    m = re.fullmatch(r"(0x[0-9a-fA-F]+|\d+)([KkMm]?)", tok.strip())
    if not m:
        raise ValueError("bad size %r" % tok)
    n = int(m.group(1), 0)
    return n * {"": 1, "k": 1024, "m": 1024 * 1024}[m.group(2).lower()]


def ota0_size(csv):
    for line in csv.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        cols = [c.strip() for c in line.split(",")]
        if cols[0] == "ota_0":
            return parse_size(cols[4])
    raise ValueError("no ota_0 row in %s" % csv)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build-dir", required=True)
    ap.add_argument("--board", required=True, choices=sorted(BOARDS))
    a = ap.parse_args()
    b = BOARDS[a.board]
    bd = Path(a.build_dir)

    try:
        limit = ota0_size(ROOT / b["csv"])
        binf = bd / "dns-sink.bin"
        size = binf.stat().st_size
        check(size <= limit * MAX_FRACTION,
              "app size %d B (%.1f%% of ota_0 %d B, max %d%%)"
              % (size, 100.0 * size / limit, limit, MAX_FRACTION * 100))
    except (OSError, ValueError) as e:
        check(False, "app size: %s" % e)

    cfg = {}
    try:
        for line in (bd / "config" / "sdkconfig.h").read_text().splitlines():
            m = re.match(r"#define\s+(CONFIG_\w+)(?:\s+(.*))?$", line)
            if m:
                cfg[m.group(1)] = (m.group(2) or "").strip()
    except OSError as e:
        check(False, "sdkconfig.h: %s" % e)
        return 1

    for sym in COMMON_REQUIRED + [b["select"], b["flash"]]:
        check(sym in cfg, "%s present" % sym)
    for sym in SEEDS:
        v = cfg.get(sym, "").strip('"')
        check(v == "", "%s is empty" % sym)
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
