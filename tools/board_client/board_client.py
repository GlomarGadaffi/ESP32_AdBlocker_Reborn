#!/usr/bin/env python3
"""HTTP client for ESP32_AdBlocker_Reborn's admin API.

Handles login, session cookie, and CSRF token once, then exposes the
board's own HTTP endpoints as plain methods. Replaces re-deriving the
login+CSRF dance in a fresh PowerShell/Python script per task, and
replaces browser automation for anything that doesn't need a human eye
on the page — flashing, metrics polling, rule edits, reloads.

Library usage:
    from board_client import BoardClient
    b = BoardClient("192.168.12.195", user="admin", password="...")
    b.metrics()["blocklist_count"]
    b.check("doubleclick.net")
    b.custom_rules("@@||doubleclick.net^")
    b.reload(wait=True)
    b.flash("build-waveshare/dns-sink.bin", wait=True)

CLI usage:
    python board_client.py --host 192.168.12.195 metrics
    python board_client.py --host 192.168.12.195 check doubleclick.net
    python board_client.py --host 192.168.12.195 reload --wait
    python board_client.py --host 192.168.12.195 flash build/dns-sink.bin --wait
    python board_client.py --host 192.168.12.195 custom-rules "@@||doubleclick.net^"
    python board_client.py --host 192.168.12.195 whitelist-add example.com
    python board_client.py --host 192.168.12.195 get /log

Credentials: --user/--password, or the BOARD_USER/BOARD_PASSWORD env vars.
Never hardcode a board password in a script that calls this — pass it in.
"""

import argparse
import http.cookiejar
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


class BoardError(RuntimeError):
    """A non-2xx response from the board, or a login failure."""


class BoardClient:
    def __init__(self, host, user="admin", password=None, timeout=8):
        self.host = host
        self.user = user
        self.password = password
        self.timeout = timeout
        self._csrf = None

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self._cj = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._cj),
            urllib.request.HTTPSHandler(context=ctx),
        )

    # ---- low-level ----

    def _url(self, path):
        return f"https://{self.host}{path}"

    def _open(self, req, timeout=None):
        try:
            return self._opener.open(req, timeout=timeout or self.timeout)
        except urllib.error.HTTPError as e:
            return e  # HTTPError is also a file-like response object

    def login(self):
        """Log in and cache the session cookie + CSRF token. Raises BoardError on bad creds."""
        if not self.password:
            raise BoardError("no password set (pass password=... or set BOARD_PASSWORD)")
        data = urllib.parse.urlencode({"user": self.user, "pass": self.password}).encode()
        req = urllib.request.Request(
            self._url("/login"), data=data, method="POST",
            headers={"Origin": f"https://{self.host}",
                     "Content-Type": "application/x-www-form-urlencoded"},
        )
        self._open(req)

        r = self._open(urllib.request.Request(self._url("/")))
        html = r.read().decode(errors="replace")
        if "var CSRF='" not in html:
            raise BoardError("login failed (no session — check user/password)")
        self._csrf = html.split("var CSRF='")[1].split("'")[0]
        return self

    def _ensure_session(self):
        if self._csrf is None:
            self.login()

    def get(self, path, raw=False):
        """GET an admin page/endpoint. Logs in automatically on first call."""
        self._ensure_session()
        r = self._open(urllib.request.Request(self._url(path)))
        body = r.read().decode(errors="replace")
        if getattr(r, "status", 200) >= 400:
            raise BoardError(f"GET {path} -> {r.status}: {body[:200]}")
        return body if raw else body

    def post(self, path, body="", content_type="application/x-www-form-urlencoded",
              raw_bytes=None, extra_timeout=None):
        """POST to an admin endpoint, CSRF token attached automatically."""
        self._ensure_session()
        data = raw_bytes if raw_bytes is not None else body.encode()
        req = urllib.request.Request(
            self._url(f"{path}?csrf={self._csrf}"), data=data, method="POST",
            headers={"X-CSRF": self._csrf, "Content-Type": content_type},
        )
        r = self._open(req, timeout=extra_timeout)
        out = r.read().decode(errors="replace")
        status = getattr(r, "status", getattr(r, "code", 200))
        if status >= 400:
            raise BoardError(f"POST {path} -> {status}: {out[:300]}")
        return status, out

    # ---- typed endpoints ----

    def metrics(self):
        """GET /metrics as a parsed dict."""
        return json.loads(self.get("/metrics"))

    def check(self, domain):
        """POST /check — returns {'verdict': 'BLOCKED'|'ALLOWED'|'REWRITE', 'raw': <html>}."""
        _, html = self.post("/check", "domain=" + urllib.parse.quote(domain))
        if "BLOCKED" in html:
            verdict = "BLOCKED"
        elif "REWRITE" in html:
            verdict = "REWRITE"
        else:
            verdict = "ALLOWED"
        return {"verdict": verdict, "raw": html}

    def custom_rules(self, text):
        """POST /custom/rules — replaces the whole custom rules list (not append)."""
        return self.post("/custom/rules", "rules=" + urllib.parse.quote(text))

    def whitelist_add(self, domain):
        return self.post("/whitelist/add", "domain=" + urllib.parse.quote(domain))

    def whitelist_remove(self, domain):
        return self.post("/whitelist/remove", "domain=" + urllib.parse.quote(domain))

    def running_slot(self):
        """Which OTA slot ('ota_0'/'ota_1') is currently running."""
        html = self.get("/")
        if "Running from: <b>" in html:
            return html.split("Running from: <b>")[1].split("</b>")[0]
        return None

    def reload(self, wait=False, poll_interval=3, max_wait=480):
        """POST /reload. With wait=True, polls /metrics until blocklist_loading goes False
        (a full multi-feed reload can take several minutes)."""
        self.post("/reload", "")
        if not wait:
            return
        start = time.time()
        while time.time() - start < max_wait:
            time.sleep(poll_interval)
            m = self.metrics()
            if m.get("blocklist_loading") is False:
                return m
        raise BoardError(f"reload did not complete within {max_wait}s "
                          f"(blocklist_loading stayed true — check for a stuck feed, see #84)")

    def flash(self, bin_path, wait=True, wait_timeout=60):
        """POST /ota/update with a merged firmware .bin. Board reboots ~10s after a
        successful upload. With wait=True, blocks until the board answers again."""
        with open(bin_path, "rb") as f:
            data = f.read()
        prev_slot = self.running_slot()
        status, out = self.post("/ota/update", raw_bytes=data,
                                 content_type="application/octet-stream",
                                 extra_timeout=60)
        self._csrf = None  # the reboot invalidates the session
        if not wait:
            return status, out
        start = time.time()
        while time.time() - start < wait_timeout:
            time.sleep(2)
            try:
                self.login()
                new_slot = self.running_slot()
                return {"prev_slot": prev_slot, "new_slot": new_slot}
            except Exception:
                continue
        raise BoardError(f"board did not come back within {wait_timeout}s after flashing")


def _env_default(name):
    return os.environ.get(name)


def main():
    # Board responses can contain non-ASCII (e.g. the REWRITE arrow); Windows
    # consoles default to a codepage that can't encode it. Force UTF-8 stdout
    # rather than let a print() crash the whole command.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host", required=True, help="board IP or hostname")
    p.add_argument("--user", default=_env_default("BOARD_USER") or "admin")
    p.add_argument("--password", default=_env_default("BOARD_PASSWORD"),
                    help="or set BOARD_PASSWORD")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("metrics")

    sp = sub.add_parser("check")
    sp.add_argument("domain")

    sp = sub.add_parser("custom-rules")
    sp.add_argument("text")

    sp = sub.add_parser("whitelist-add")
    sp.add_argument("domain")

    sp = sub.add_parser("whitelist-remove")
    sp.add_argument("domain")

    sp = sub.add_parser("reload")
    sp.add_argument("--wait", action="store_true")

    sp = sub.add_parser("flash")
    sp.add_argument("bin_path")
    sp.add_argument("--no-wait", action="store_true")

    sp = sub.add_parser("get")
    sp.add_argument("path")

    sp = sub.add_parser("post")
    sp.add_argument("path")
    sp.add_argument("body", nargs="?", default="")

    args = p.parse_args()

    if not args.password:
        print("error: no password (--password or BOARD_PASSWORD env var)", file=sys.stderr)
        sys.exit(1)

    b = BoardClient(args.host, user=args.user, password=args.password)

    try:
        if args.cmd == "metrics":
            print(json.dumps(b.metrics(), indent=2))
        elif args.cmd == "check":
            print(json.dumps(b.check(args.domain)))
        elif args.cmd == "custom-rules":
            status, out = b.custom_rules(args.text)
            print(f"status={status}")
        elif args.cmd == "whitelist-add":
            status, out = b.whitelist_add(args.domain)
            print(f"status={status}")
        elif args.cmd == "whitelist-remove":
            status, out = b.whitelist_remove(args.domain)
            print(f"status={status}")
        elif args.cmd == "reload":
            result = b.reload(wait=args.wait)
            print(json.dumps(result) if result else "reload triggered")
        elif args.cmd == "flash":
            result = b.flash(args.bin_path, wait=not args.no_wait)
            print(json.dumps(result))
        elif args.cmd == "get":
            print(b.get(args.path))
        elif args.cmd == "post":
            status, out = b.post(args.path, args.body)
            print(f"status={status}\n{out}")
    except BoardError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
