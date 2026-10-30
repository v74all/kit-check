import base64
import importlib.util
import socket
import struct
import threading
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("kc", Path(__file__).resolve().parent.parent / "kit-check.py")
kc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kc)


def answer(query, rcode, records=()):
    """A response to `query` with the given rcode and (type, rdata) answers."""
    tid = query[:2]
    i = 12
    while query[i]:
        i += 1 + query[i]
    question = query[12:i + 5]
    head = tid + struct.pack(">HHHHH", 0x8180 | rcode, 1, len(records), 0, 0)
    body = b"".join(b"\xc0\x0c" + struct.pack(">HHIH", t, 1, 60, len(r)) + r for t, r in records)
    return head + question + body


class FakeDNS:
    """UDP DNS server on 127.0.0.1: 'dnstt' answers TXT polls, 'nx' says NXDOMAIN, 'silent' drops."""

    def __init__(self, mode):
        self.mode = mode
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.names = []
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                q, addr = self.sock.recvfrom(4096)
            except OSError:
                return
            i, labels = 12, []
            while q[i]:
                labels.append(q[i + 1:i + 1 + q[i]].decode())
                i += 1 + q[i]
            self.names.append(".".join(labels))
            if self.mode == "dnstt":
                self.sock.sendto(answer(q, 0, [(kc.QTYPE_TXT, b"\x00")]), addr)
            elif self.mode == "nx":
                self.sock.sendto(answer(q, 3), addr)
            elif self.mode == "a":
                self.sock.sendto(answer(q, 0, [(kc.QTYPE_A, socket.inet_aton("10.10.34.36"))]), addr)

    def close(self):
        self.sock.close()


class WireTest(unittest.TestCase):
    def test_query_roundtrip(self):
        tid, q = kc.build_query("example.com", kc.QTYPE_A)
        resp = answer(q, 0, [(kc.QTYPE_A, socket.inet_aton("93.184.215.14"))])
        rcode, ans = kc.parse_response(resp, tid)
        self.assertEqual(rcode, 0)
        self.assertEqual(kc.a_records(ans), ["93.184.215.14"])

    def test_wrong_id_is_ignored(self):
        tid, q = kc.build_query("example.com", kc.QTYPE_A)
        self.assertIsNone(kc.parse_response(answer(q, 0), (tid + 1) & 0xFFFF))

    def test_poll_name_looks_like_a_dnstt_poll(self):
        name = kc.poll_name("t.example.com")
        label, _, rest = name.partition(".")
        self.assertEqual(rest, "t.example.com")
        self.assertLessEqual(len(label), 63)
        raw = base64.b32decode(label.upper() + "=" * (-len(label) % 8))
        self.assertEqual(len(raw), 12)
        self.assertEqual(raw[8], 224 + 3)   # padding marker, then 3 bytes

    def test_hijack_ranges(self):
        self.assertTrue(kc.hijacked("10.10.34.36"))
        self.assertTrue(kc.hijacked("127.0.0.1"))
        self.assertFalse(kc.hijacked("198.51.100.80"))
        self.assertFalse(kc.hijacked("104.20.23.154"))


class TunnelTest(unittest.TestCase):
    def run_tunnel(self, mode):
        srv = FakeDNS(mode)
        try:
            return kc.check_tunnel("t.example.com", ["127.0.0.1:%d" % srv.port], 1.0), srv.names
        finally:
            srv.close()

    def test_dnstt_server_answers(self):
        res, names = self.run_tunnel("dnstt")
        self.assertTrue(res.ok, res.note)
        self.assertTrue(names[0].endswith(".t.example.com"))

    def test_no_delegation(self):
        res, _ = self.run_tunnel("nx")
        self.assertFalse(res.ok)
        self.assertIn("nxdomain", res.note)

    def test_silent_resolver(self):
        res, _ = self.run_tunnel("silent")
        self.assertFalse(res.ok)
        self.assertIn("no answer", res.note)

    def test_no_resolver_is_a_skip(self):
        res = kc.check_tunnel("t.example.com", [], 1.0)
        self.assertTrue(res.skipped)


class RungTest(unittest.TestCase):
    def rung(self, **ok):
        return kc.best_rung([kc.Result(n, v, "") for n, v in ok.items()])

    def test_ladder(self):
        self.assertEqual(self.rung(dns=True, server=True, cdn=True), 1)
        self.assertEqual(self.rung(dns=True, server=False, cdn=True), 2)
        self.assertEqual(self.rung(dns=True, doh=True, server=False), 3)
        self.assertEqual(self.rung(dns=True, doh=False, tunnel=True), 4)
        self.assertEqual(self.rung(dns=False, doh=False, tunnel=False), 5)

    def test_skipped_does_not_count(self):
        self.assertEqual(kc.best_rung([kc.Result("tunnel", True, "", skipped=True)]), 5)


class LinksTest(unittest.TestCase):
    def test_links_file(self):
        import tempfile
        text = "\n".join([
            "# mine",
            "vless://00000000-0000-4000-8000-000000000001@203.0.113.7:8443?security=reality&sni=www.example.com&type=xhttp#a",
            "vless://00000000-0000-4000-8000-000000000002@104.16.1.2:443?security=tls&sni=sub.example.com&type=ws#b",
            "vless://00000000-0000-4000-8000-000000000003@198.51.100.9:443?security=reality&sni=other.example#ignored",
            "tunnel t.example.com",
        ])
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write(text)
        self.assertEqual(kc.read_targets(f.name),
                         ("203.0.113.7:8443", "www.example.com", "sub.example.com", "104.16.1.2", "t.example.com"))

    def test_cdn_by_name(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("trojan://pw@sub.example.com:443?type=ws&host=sub.example.com#c\n")
        self.assertEqual(kc.read_targets(f.name), (None, None, "sub.example.com", None, None))


class OutputTest(unittest.TestCase):
    def test_lines_fit_69_columns(self):
        notes = [kc.Result("dns-out", False, "udp/53 to 1.1.1.1, 8.8.8.8, 9.9.9.9: no answer"),
                 kc.Result("server", False, "198.51.100.10:443: reset after client hello"),
                 kc.Result("cdn", True, "cdn.lab.test: tls ok, colo FRA"),
                 kc.Result("tunnel", True, "t.lab.test answers via 100.64.0.1")]
        for r in notes:
            self.assertLessEqual(len(r.line()), 69, r.line())
        for text in kc.RUNGS.values():
            self.assertLessEqual(len("rung 5 of 5: " + text), 69, text)

    def test_closed_port(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        self.assertEqual(kc.tls_stage("127.0.0.1", port, "x", 1.0, kc.ssl.create_default_context()), "port closed")


if __name__ == "__main__":
    unittest.main()
