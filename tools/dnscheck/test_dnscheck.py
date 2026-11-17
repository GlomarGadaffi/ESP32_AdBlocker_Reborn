#!/usr/bin/env python3
"""Tests for dnscheck against the local fake_dns server. Loopback only."""

import contextlib
import http.server
import io
import json
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dnscheck  # noqa: E402
import fake_dns  # noqa: E402


def run(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = dnscheck.main(argv)
    return code, buf.getvalue()


class FakeMetrics:
    """Tiny HTTP server returning successive /metrics bodies; records Cookie headers."""

    def __init__(self, bodies):
        self.bodies = list(bodies)
        self.cookies = []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                outer.cookies.append(self.headers.get("Cookie"))
                i = min(len(outer.cookies) - 1, len(outer.bodies) - 1)
                data = json.dumps(outer.bodies[i]).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d/metrics" % self.httpd.server_address[1]
        self.t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.t.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def metrics(total, table_full=0, timeouts=0, heap_free=100000, heap_largest=50000):
    return {"queries_total": total, "dropped": {"table_full": table_full, "mbox_pressure": 0},
            "upstream_timeouts": timeouts, "heap_free": heap_free, "heap_largest": heap_largest}


class Base(unittest.TestCase):
    def serve(self, fault="correct", **kw):
        srv = fake_dns.FakeDns(fault=fault, **kw)
        srv.start()
        self.addCleanup(srv.stop)
        return srv

    def check(self, srv, *extra, tcp=False):
        argv = ["--server", "127.0.0.1", "--port", str(srv.port), "--seed", "7",
                "--timeout", "0.5", "--settle", "0.1"] + list(extra)
        if tcp:
            argv.append("--tcp")
        return run(argv)


class TestCorrect(Base):
    def test_udp_passes(self):
        srv = self.serve()
        code, out = self.check(srv, "--count", "40", "--concurrency", "8")
        self.assertEqual(code, 0, out)
        self.assertIn("sent 40 answered 40 mismatched 0 unanswered 0", out)

    def test_tcp_passes(self):
        srv = self.serve()
        code, out = self.check(srv, "--count", "40", "--concurrency", "6", tcp=True)
        self.assertEqual(code, 0, out)
        self.assertIn("sent 40 answered 40 mismatched 0 unanswered 0", out)

    def test_burst_passes(self):
        srv = self.serve()
        code, out = self.check(srv, "--count", "4", "--same-name", "12")
        self.assertEqual(code, 0, out)
        self.assertIn("answered=12 unanswered=0 duplicates=0", out)
        self.assertIn("sent 16 answered 16", out)

    def test_seed_is_deterministic(self):
        a = dnscheck.build_queries(30, 5, None)
        b = dnscheck.build_queries(30, 5, None)
        self.assertEqual([q.packet[2:] for q in a], [q.packet[2:] for q in b])
        self.assertEqual(len({q.txid for q in a}), 30)
        self.assertTrue(any(q.edns for q in a) and any(not q.edns for q in a))
        self.assertTrue(any(q.qtype == 28 for q in a) and any(q.qtype == 1 for q in a))

    def test_usage_error_is_2(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as cm:
            run(["--count", "3"])
        self.assertEqual(cm.exception.code, 2)


class TestFaultsUdp(Base):
    def expect(self, fault, check, *extra, **kw):
        srv = self.serve(fault, **kw)
        code, out = self.check(srv, "--count", "24", "--concurrency", "6", *extra)
        self.assertEqual(code, 1, out)
        self.assertIn("check=" + check, out)

    def test_wrong_txid(self):
        self.expect("wrong_txid", "txid")

    def test_case_not_echoed(self):
        self.expect("case_not_echoed", "question")

    def test_oversize_without_tc(self):
        self.expect("oversize_no_tc", "size")

    def test_loop_pointer(self):
        self.expect("loop_pointer", "compression")

    def test_drop_every_nth(self):
        self.expect("drop_nth", "unanswered", drop_every=3)

    def test_duplicate_replies(self):
        self.expect("duplicate", "duplicate")

    def test_wrong_source(self):
        self.expect("wrong_source", "source")

    def test_mismatch_line_names_query_expected_got(self):
        srv = self.serve("wrong_txid")
        _, out = self.check(srv, "--count", "3")
        line = [l for l in out.splitlines() if "check=txid" in l][0]
        self.assertIn("query=", line)
        self.assertIn("expected=", line)
        self.assertIn("got=", line)

    def test_burst_duplicates_reported(self):
        srv = self.serve("duplicate")
        code, out = self.check(srv, "--count", "1", "--same-name", "5")
        self.assertEqual(code, 1, out)
        self.assertNotIn("duplicates=0", out)

    def test_burst_drops_reported(self):
        srv = self.serve("drop_nth", drop_every=2)
        code, out = self.check(srv, "--count", "1", "--same-name", "6")
        self.assertEqual(code, 1, out)
        self.assertNotIn("unanswered=0", out.split("burst")[1].splitlines()[0])


class TestFaultsTcp(Base):
    def expect(self, fault, check, **kw):
        srv = self.serve(fault, **kw)
        code, out = self.check(srv, "--count", "12", "--concurrency", "3", tcp=True)
        self.assertEqual(code, 1, out)
        self.assertIn("check=" + check, out)

    def test_wrong_txid(self):
        self.expect("wrong_txid", "txid")

    def test_case_not_echoed(self):
        self.expect("case_not_echoed", "question")

    def test_loop_pointer(self):
        self.expect("loop_pointer", "compression")

    def test_drop_every_nth(self):
        self.expect("drop_nth", "unanswered", drop_every=3)


class TestMetricsWindow(Base):
    def test_clean_window_reports_deltas(self):
        srv = self.serve()
        fm = FakeMetrics([metrics(1000, heap_free=90000), metrics(1020, table_full=0, heap_free=89000)])
        self.addCleanup(fm.close)
        code, out = self.check(srv, "--count", "20", "--metrics-url", fm.url, "--cookie", "sid=abc")
        self.assertEqual(code, 0, out)
        self.assertIn("queries_total", out)
        self.assertIn("+20", out)
        self.assertIn("heap_free", out)
        self.assertEqual(fm.cookies, ["sid=abc", "sid=abc"])

    def test_contaminated_window_is_3(self):
        srv = self.serve()
        fm = FakeMetrics([metrics(1000), metrics(2500)])
        self.addCleanup(fm.close)
        code, out = self.check(srv, "--count", "20", "--metrics-url", fm.url)
        self.assertEqual(code, 3, out)
        self.assertIn("window contaminated", out)

    def test_contaminated_beats_mismatch(self):
        srv = self.serve("wrong_txid")
        fm = FakeMetrics([metrics(1000), metrics(5000)])
        self.addCleanup(fm.close)
        code, out = self.check(srv, "--count", "5", "--metrics-url", fm.url)
        self.assertEqual(code, 3, out)

    def test_counter_reset_is_contaminated(self):
        srv = self.serve()
        fm = FakeMetrics([metrics(1000), metrics(3)])
        self.addCleanup(fm.close)
        code, out = self.check(srv, "--count", "5", "--metrics-url", fm.url)
        self.assertEqual(code, 3, out)

    def test_tolerance_allows_small_extra(self):
        srv = self.serve()
        fm = FakeMetrics([metrics(1000), metrics(1000 + 10 + 15)])
        self.addCleanup(fm.close)
        code, out = self.check(srv, "--count", "10", "--metrics-url", fm.url, "--tolerance", "20")
        self.assertEqual(code, 0, out)


if __name__ == "__main__":
    unittest.main()
