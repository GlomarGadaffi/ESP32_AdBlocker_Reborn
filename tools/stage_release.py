#!/usr/bin/env python3
"""Stage a firmware release: portable equivalent of tools/make-release.ps1.

For each board it copies the four flashable images named in the build's
flash_args into <out-root>/docs/firmware/<version>/ as
"<board>-<version>-<stem>.bin", writes manifest.json, updates
docs/firmware/index.json, and writes <out-root>/release/ (the same files plus
SHA256SUMS) for upload as GitHub Release assets.

It refuses (exit 1) when:
  * a build's config/ carries a non-empty CONFIG_ADBLOCK_WIFI_SSID/PASSWORD
    (the 1.2.0 release shipped a home Wi-Fi PSK that way),
  * version.txt does not equal --version,
  * an app image's esp_app_desc version is not "<version>+<board>".

Stdlib only.

Usage:
  stage_release.py --version 1.6.0 \
      --builds t-eth-elite=build waveshare-s3-eth=build-waveshare \
               generic-s3-wifi=build-wifi [--out-root DIR] [--version-file F]
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import struct
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Board ids are the ADBLOCK_BOARD_TAG values in CMakeLists.txt. Keep in sync
# with make-release.ps1.
BOARDS = {
    "t-eth-elite": "LilyGO T-ETH-Elite",
    "waveshare-s3-eth": "Waveshare ESP32-S3-ETH",
    "generic-s3-wifi": "Generic ESP32-S3 (Wi-Fi only)",
}

# Files in <build>/config/ that can carry the Wi-Fi seed.
CONFIG_FILES = ("sdkconfig", "sdkconfig.h", "sdkconfig.json", "sdkconfig.cmake")
# Key, mandatory separator (=, :, or space), then a NON-empty quoted value.
# The separator must be mandatory: in sdkconfig.json an empty seed reads
# "ADBLOCK_WIFI_SSID": "" and a lax pattern pairs the key's closing quote
# with the next key's opening quote, refusing every real build.
SEED_RE = re.compile(r'ADBLOCK_WIFI_(SSID|PASSWORD)\b"?(?:\s*[=:]\s*|\s+)"((?:[^"\\]|\\.)+)"')

# esp_image_header_t (24) + first esp_image_segment_header_t (8) precede
# esp_app_desc_t; its version[32] sits 16 bytes in (magic, secure_version,
# reserv1[2]).
APP_DESC_OFFSET = 32
APP_DESC_MAGIC = 0xABCD5432
APP_DESC_VERSION_OFFSET = APP_DESC_OFFSET + 16
APP_DESC_VERSION_LEN = 32


class Refuse(Exception):
    pass


def part_role(source):
    s = source.lower()
    if "bootloader" in s:
        return "bootloader", "bootloader"
    if "partition" in s and "table" in s:
        return "partition-table", "partition-table"
    if "ota_data" in s:
        return "ota-data", "ota_data_initial"
    return "app", "app"


def read_flash_args(path):
    settings = None
    parts = []
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            if line.startswith("--"):
                settings = {}
                tok = line.split()
                for i in range(len(tok) - 1):
                    if tok[i] == "--flash-mode":
                        settings["mode"] = tok[i + 1]
                    elif tok[i] == "--flash-freq":
                        settings["freq"] = tok[i + 1]
                    elif tok[i] == "--flash-size":
                        settings["size"] = tok[i + 1]
                continue
            m = re.match(r"^(0[xX][0-9a-fA-F]+|\d+)\s+(\S.*)$", line)
            if m:
                parts.append((int(m.group(1), 0), m.group(2).strip()))
    if not settings:
        raise Refuse("no --flash-* settings line in %s" % path)
    if not parts:
        raise Refuse("no offset/file entries in %s" % path)
    return settings, parts


def check_wifi_seed(board, build_dir):
    cfg_dir = os.path.join(build_dir, "config")
    found = False
    for name in CONFIG_FILES:
        p = os.path.join(cfg_dir, name)
        if not os.path.isfile(p):
            continue
        found = True
        with open(p, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = SEED_RE.search(line)
                if m:
                    raise Refuse(
                        "%s: %s has ADBLOCK_WIFI_%s set to a non-empty value "
                        "(value not shown). Blank the seed and rebuild; boards "
                        "keep Wi-Fi in NVS." % (board, p, m.group(1)))
    if not found:
        raise Refuse("%s: no config/sdkconfig* under %s, cannot prove the "
                     "Wi-Fi seed is empty" % (board, build_dir))


def app_version(path):
    with open(path, "rb") as f:
        head = f.read(APP_DESC_VERSION_OFFSET + APP_DESC_VERSION_LEN)
    if len(head) < APP_DESC_VERSION_OFFSET + APP_DESC_VERSION_LEN:
        raise Refuse("%s too short to hold an app descriptor" % path)
    if struct.unpack_from("<I", head, APP_DESC_OFFSET)[0] != APP_DESC_MAGIC:
        raise Refuse("%s has no esp_app_desc magic at 0x%x" % (path, APP_DESC_OFFSET))
    raw = head[APP_DESC_VERSION_OFFSET:APP_DESC_VERSION_OFFSET + APP_DESC_VERSION_LEN]
    return raw.split(b"\0", 1)[0].decode("ascii", "replace")


def write_json(path, obj):
    # No BOM, no trailing newline: matches make-release.ps1 output.
    with open(path, "wb") as f:
        f.write(json.dumps(obj, indent=2).encode("utf-8"))


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def stage(args):
    version = args.version
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise Refuse("--version %r is not X.Y.Z" % version)

    if args.date and not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", args.date):
        raise Refuse("--date %r is not YYYY-MM-DD" % args.date)

    vfile = args.version_file or os.path.join(REPO_ROOT, "version.txt")
    with open(vfile, encoding="utf-8") as f:
        file_ver = f.readline().strip()
    if file_ver != version:
        raise Refuse("version.txt says %r but --version is %r" % (file_ver, version))

    builds = {}
    for spec in args.builds:
        board, sep, bdir = spec.partition("=")
        if not sep or board not in BOARDS:
            raise Refuse("bad --builds entry %r (boards: %s)" % (spec, ", ".join(BOARDS)))
        builds[board] = bdir
    missing = [b for b in BOARDS if b not in builds]
    if missing:
        raise Refuse("missing builds for: %s" % ", ".join(missing))

    # All checks before anything is written.
    plans = {}
    for board in BOARDS:
        bdir = builds[board]
        fa = os.path.join(bdir, "flash_args")
        if not os.path.isfile(fa):
            raise Refuse("%s: %s not found" % (board, fa))
        check_wifi_seed(board, bdir)
        settings, parts = read_flash_args(fa)
        plan = []
        for offset, source in parts:
            src = os.path.join(bdir, source.replace("/", os.sep))
            root = os.path.realpath(bdir)
            if os.path.commonpath([root, os.path.realpath(src)]) != root:
                raise Refuse("%s: flash_args entry %r escapes the build dir"
                             % (board, source))
            if not os.path.isfile(src):
                raise Refuse("%s: flash_args references %s but %s is missing"
                             % (board, source, src))
            role, stem = part_role(source)
            if role == "app":
                got = app_version(src)
                want = "%s+%s" % (version, board)
                if got != want:
                    raise Refuse("%s: app image version is %r, expected %r"
                                 % (board, got, want))
            plan.append((offset, src, role, stem))
        plans[board] = (settings, plan)

    out_root = os.path.abspath(args.out_root or REPO_ROOT)
    fw_dir = os.path.join(out_root, "docs", "firmware")
    pages = os.path.join(fw_dir, version)
    bundle = os.path.join(out_root, "release")
    if os.path.isdir(pages) and os.listdir(pages) and not args.replace:
        raise Refuse("%s already exists and is not empty; published firmware "
                     "is never overwritten (pass --replace to restage)" % pages)
    for d in (pages, bundle):
        if os.path.isdir(d):
            shutil.rmtree(d)
        os.makedirs(d)

    manifest_boards = {}
    top_flash = None
    for board in BOARDS:
        settings, plan = plans[board]
        bflash = {"size": settings.get("size"), "mode": settings.get("mode"),
                  "freq": settings.get("freq")}
        if top_flash is None:
            top_flash = dict(bflash)
        mparts = []
        for offset, src, role, stem in plan:
            name = "%s-%s-%s.bin" % (board, version, stem)
            shutil.copyfile(src, os.path.join(pages, name))
            mparts.append({"offset": offset, "file": name, "role": role,
                           "size": os.path.getsize(os.path.join(pages, name))})
        manifest_boards[board] = {"name": BOARDS[board], "flash": bflash,
                                  "parts": mparts}
    write_json(os.path.join(pages, "manifest.json"),
               {"version": version, "boards": manifest_boards, "flash": top_flash})

    files = []
    for name in sorted(os.listdir(pages)):
        if not name.endswith((".bin", ".json")):
            continue
        shutil.copyfile(os.path.join(pages, name), os.path.join(bundle, name))
        files.append({"name": name, "size": os.path.getsize(os.path.join(pages, name))})

    # index.json: merge, newest first, idempotent (a re-run keeps the date).
    index_path = os.path.join(fw_dir, "index.json")
    releases = []
    if os.path.isfile(index_path):
        with open(index_path, encoding="utf-8") as f:
            try:
                releases = json.load(f).get("releases", [])
            except (ValueError, AttributeError):
                raise Refuse("%s is not valid index JSON; not overwriting" % index_path)
    old = next((r for r in releases if r.get("version") == version), None)
    date = args.date or (old or {}).get("date") or \
        datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    entry = {"version": version, "tag": "v" + version, "date": date, "files": files}
    releases = [entry] + [r for r in releases if r.get("version") != version]
    tmp = index_path + ".tmp"
    write_json(tmp, {"latest": version, "releases": releases})
    os.replace(tmp, index_path)

    with open(os.path.join(bundle, "SHA256SUMS"), "w", encoding="utf-8", newline="\n") as f:
        for name in sorted(os.listdir(bundle)):
            if name != "SHA256SUMS":
                f.write("%s  %s\n" % (sha256(os.path.join(bundle, name)), name))

    print("Staged %d files for %s" % (len(files), version))
    print("  %s" % pages)
    print("  %s" % bundle)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--version", required=True)
    ap.add_argument("--builds", nargs="+", required=True, metavar="BOARD=BUILDDIR")
    ap.add_argument("--out-root", help="root holding docs/firmware and release/ (default: repo root)")
    ap.add_argument("--version-file", help="version.txt to check against (default: repo version.txt)")
    ap.add_argument("--replace", action="store_true",
                    help="allow restaging over an existing non-empty docs/firmware/<version>")
    ap.add_argument("--date", help="YYYY-MM-DD for a new index entry (default: today UTC)")
    args = ap.parse_args(argv)
    try:
        stage(args)
    except Refuse as e:
        print("REFUSED: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
