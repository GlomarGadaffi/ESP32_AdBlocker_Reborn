# board_client.py — HTTP client for the admin API

Handles login, the session cookie, and the CSRF token once, then exposes the
board's own endpoints as plain methods (or CLI subcommands). Written after a
session that kept re-deriving the same login+CSRF dance per PowerShell/Python
script, and kept hitting browser-automation flakiness for tasks (flashing,
metrics polling, rule edits) that never needed a human eye on the page.

```
python board_client.py --host 192.168.12.195 metrics
python board_client.py --host 192.168.12.195 check doubleclick.net
python board_client.py --host 192.168.12.195 custom-rules "@@||doubleclick.net^"
python board_client.py --host 192.168.12.195 reload --wait
python board_client.py --host 192.168.12.195 flash build-waveshare/dns-sink.bin
python board_client.py --host 192.168.12.195 whitelist-add example.com
python board_client.py --host 192.168.12.195 get /log
```

Credentials: `--user`/`--password`, or the `BOARD_USER`/`BOARD_PASSWORD` env
vars. Never hardcode a board password into a script that imports this module.

As a library:

```python
from board_client import BoardClient
b = BoardClient("192.168.12.195", user="admin", password="...")
b.metrics()["blocklist_count"]
b.check("doubleclick.net")          # {"verdict": "BLOCKED", "raw": "<html>..."}
b.reload(wait=True)                 # polls /metrics until blocklist_loading is False
b.flash("build/dns-sink.bin")       # uploads, waits for reboot, re-logs in, returns the slot flip
```

`get`/`post` are the escape hatch for any endpoint that doesn't have a typed
wrapper yet — everything goes through the same session/CSRF machinery.

## What this replaces

Not browser automation in general — for anything that needs a human eye on
rendered HTML (visual layout bugs, a page that behaves differently under
`document.hidden`, confirming a fix like #110's actually renders), the Chrome
tools are still the right call. This is for the other half: driving the admin
API as a scriptable, testable interface. In particular:

- `reload(wait=True)` and `flash(wait=True)` encode the polling/retry
  discipline a manual test otherwise has to reinvent every time (a full
  multi-feed reload can take several minutes; a flash needs the board to
  reboot, and the session it invalidates needs a fresh login, not a retry
  against the stale cookie).
- A `BoardError` on a failed login or a non-2xx response, instead of a script
  silently reading a login page's HTML as if it were the JSON it expected —
  this was a real failure mode hit while building the earlier ad-hoc version
  of this pattern (`bench117.py`), where an expired session on `/metrics`
  came back as the login page and got parsed as empty JSON.

## Gotchas this already found

- **Windows console codepage**: a board response containing non-ASCII (e.g.
  the `→` in a REWRITE verdict's arrow) will crash a bare `print()` on the
  default `cp1252` console. The CLI reconfigures stdout to UTF-8 on startup;
  a caller using this as a library and printing raw response text on Windows
  should do the same.
- **Sessions expire** (30 min idle per the board's own auth code) — every
  method here re-logs in lazily on first use, but a long-lived script holding
  a `BoardClient` across a real gap (waiting on a slow reload, a human
  decision) should expect the next call to trigger a fresh login
  transparently, not assume the original session is still good.
