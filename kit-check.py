#!/usr/bin/env python3
"""kit-check: which way out still works on the network you are on, right now.

Run it with your VPN OFF, on the network you are stuck on (mobile data, home wifi).
It only talks to the well-known public resolvers listed below and to the servers you name.

    python3 kit-check.py                                  resolvers only
    python3 kit-check.py links.txt                        + what your own configs need
    python3 kit-check.py --server 203.0.113.7 --sni www.example.com
                                                          your own REALITY / TLS server
    python3 kit-check.py --cdn sub.example.com            your config behind Cloudflare
    python3 kit-check.py --tunnel t.example.com           your DNS tunnel domain

links.txt holds your own vless:// or trojan:// links, one per line, and `tunnel t.example.com`
for a DNS tunnel. A REALITY link becomes the server check, a TLS link the CDN check.

Standard library only, Python 3.8+ (Linux, macOS, Windows, Termux on Android).
"""
import argparse
import base64
import ipaddress
import os
import secrets
import socket
import ssl
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, unquote, urlsplit

VERSION = "1.0.0"

# a name that exists everywhere and is rarely filtered
PROBE_NAME = "example.com"
# public resolvers people in Iran try first; plain UDP/53 and DoH on the same addresses
PUBLIC_DNS = [("1.1.1.1", "cloudflare-dns.com"), ("8.8.8.8", "dns.google"), ("9.9.9.9", "dns.quad9.net")]
# DNS hijacks answer with private addresses (Iran's block page lives in 10.10.34.0/24)
HIJACK_NETS = [ipaddress.ip_network(n) for n in ("0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]

QTYPE_A, QTYPE_TXT, QTYPE_OPT = 1, 16, 41
RCODES = {0: "noerror", 1: "formerr", 2: "servfail", 3: "nxdomain", 4: "notimp", 5: "refused"}
B32 = "abcdefghijklmnopqrstuvwxyz234567"

RUNGS = {
    1: "your own server works",
    2: "your config behind the CDN works",
    3: "big providers answer: try Snowflake, WebTunnel, Psiphon",
    4: "only DNS gets out: use a DNS tunnel",
    5: "nothing international answers right now",
}


class Result:
    def __init__(self, name, ok, note, skipped=False):
        self.name, self.ok, self.note, self.skipped = name, ok, note, skipped

    def line(self):
        word = "skip" if self.skipped else ("ok" if self.ok else "block")
        return "  {:<6} {:<8} {}".format(word, self.name, self.note)


# --- DNS wire format -----------------------------------------------------------

def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna") if label else b""
        if not 0 < len(raw) < 64:
            raise ValueError("bad label in %r" % name)
        out += bytes([len(raw)]) + raw
    return out + b"\0"


def build_query(name, qtype, edns=True):
    tid = secrets.randbits(16)
    head = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 1 if edns else 0)   # RD = 1
    msg = head + encode_name(name) + struct.pack(">HH", qtype, 1)
    if edns:
        msg += b"\0" + struct.pack(">HHIH", QTYPE_OPT, 1232, 0, 0)
    return tid, msg


def _skip_name(msg, i):
    while True:
        n = msg[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += 1 + n


def parse_response(msg, tid):
    """(rcode, [(type, rdata)]) or None when it is not the answer to our query."""
    if len(msg) < 12:
        return None
    rid, flags, qd, an, _, _ = struct.unpack(">HHHHHH", msg[:12])
    if rid != tid or not flags & 0x8000:
        return None
    i = 12
    for _ in range(qd):
        i = _skip_name(msg, i) + 4
    answers = []
    for _ in range(an):
        i = _skip_name(msg, i)
        rtype, _, _, rdlen = struct.unpack(">HHIH", msg[i:i + 10])
        i += 10
        answers.append((rtype, msg[i:i + rdlen]))
        i += rdlen
    return flags & 0xF, answers


def udp_query(server, name, qtype, timeout, tries=2, port=53):
    """Ask one resolver over UDP. Returns (rcode, answers) or raises socket.timeout."""
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    tid, msg = build_query(name, qtype)
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout / tries)
        for _ in range(tries):
            s.sendto(msg, (server, port))
            end = time.monotonic() + timeout / tries
            try:
                while time.monotonic() < end:
                    got = parse_response(s.recv(4096), tid)
                    if got:
                        return got
            except socket.timeout:
                continue
    raise socket.timeout("no answer")


def a_records(answers):
    return [socket.inet_ntoa(r) for t, r in answers if t == QTYPE_A and len(r) == 4]


def hijacked(ip):
    a = ipaddress.ip_address(ip)
    return any(a in n for n in HIJACK_NETS)


def poll_name(domain):
    """A name a dnstt server answers like a client poll: 8-byte client id + 3 bytes of padding."""
    raw = secrets.token_bytes(8) + bytes([224 + 3]) + secrets.token_bytes(3)
    enc = base64.b32encode(raw).decode().rstrip("=").lower()
    return enc + "." + domain.rstrip(".")


def system_resolvers():
    """Resolver addresses from resolv.conf (Linux, macOS, Termux). Empty on Windows / Android without it."""
    paths = ["/etc/resolv.conf"]
    if os.environ.get("PREFIX"):
        paths.insert(0, os.path.join(os.environ["PREFIX"], "etc/resolv.conf"))
    for p in paths:
        try:
            with open(p) as f:
                found = [ln.split()[1] for ln in f if ln.startswith("nameserver") and len(ln.split()) > 1]
        except OSError:
            continue
        found = [ip.split("%")[0] for ip in found if not ip.startswith("127.0.0.53")]
        if found:
            return found
    return []


# --- checks --------------------------------------------------------------------

def check_dns():
    try:
        ips = sorted({ai[4][0] for ai in socket.getaddrinfo(PROBE_NAME, 443, socket.AF_INET, socket.SOCK_STREAM)})
    except OSError as e:
        return Result("dns", False, "%s does not resolve (%s)" % (PROBE_NAME, short_err(e)))
    if any(hijacked(ip) for ip in ips):
        return Result("dns", False, "%s -> %s (hijacked)" % (PROBE_NAME, ips[0]))
    return Result("dns", True, "%s resolves (system resolver)" % PROBE_NAME)


def check_dns_out(timeout):
    def one(ip):
        try:
            rcode, ans = udp_query(ip, PROBE_NAME, QTYPE_A, timeout)
        except OSError:
            return False
        ips = a_records(ans)
        return rcode == 0 and bool(ips) and not any(hijacked(x) for x in ips)

    ips = [ip for ip, _ in PUBLIC_DNS]
    with ThreadPoolExecutor(len(ips)) as ex:
        answered = list(ex.map(one, ips))
    good = [ip for ip, ok in zip(ips, answered) if ok]
    bad = [ip for ip, ok in zip(ips, answered) if not ok]
    if good:
        return Result("dns-out", True, "udp/53 to %s answers" % ", ".join(good))
    return Result("dns-out", False, "udp/53 to %s: no answer" % ", ".join(bad))


def https_get(ip, port, host, path, timeout, ctx, accept="*/*"):
    """One HTTP/1.1 GET over TLS to ip:port with SNI and Host = host. Returns (status, body)."""
    with socket.create_connection((ip, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            req = "GET %s HTTP/1.1\r\nHost: %s\r\nAccept: %s\r\nUser-Agent: kit-check/%s\r\nConnection: close\r\n\r\n" % (
                path, host, accept, VERSION)
            s.sendall(req.encode())
            data = b""
            while len(data) < 65536:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1]) if lines and len(lines[0].split()) > 1 else 0
    if any(ln.lower().replace(" ", "") == "transfer-encoding:chunked" for ln in lines[1:]):
        body = dechunk(body)
    return status, body


def dechunk(body):
    out = b""
    while body:
        size_line, _, rest = body.partition(b"\r\n")
        size = int(size_line.split(b";")[0] or b"0", 16)
        if size == 0:
            break
        out, body = out + rest[:size], rest[size + 2:]
    return out


def check_doh(timeout, ctx):
    def one(target):
        ip, host = target
        _, msg = build_query(PROBE_NAME, QTYPE_A, edns=False)
        msg = b"\0\0" + msg[2:]   # RFC 8484: id 0 for caching
        q = base64.urlsafe_b64encode(msg).decode().rstrip("=")
        try:
            status, body = https_get(ip, 443, host, "/dns-query?dns=" + q, timeout, ctx, "application/dns-message")
        except (OSError, ssl.SSLError, ValueError) as e:
            return None, short_err(e)
        got = parse_response(body, 0) if status == 200 else None
        if got and got[0] == 0 and a_records(got[1]):
            return host, ""
        return None, "http %d" % status

    with ThreadPoolExecutor(2) as ex:
        res = list(ex.map(one, PUBLIC_DNS[:2]))
    good = [h for h, _ in res if h]
    why = next((w for h, w in res if w), "")
    if good:
        return Result("doh", True, "%s answers over https" % ", ".join(good))
    return Result("doh", False, "%s: %s" % (", ".join(h for _, h in PUBLIC_DNS[:2]), why))


def tls_stage(ip, port, sni, timeout, ctx):
    """None when TCP + TLS complete, else where it stopped."""
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except socket.timeout:
        return "tcp timeout"
    except ConnectionRefusedError:
        return "port closed"
    except OSError as e:
        return "tcp " + short_err(e)
    try:
        with ctx.wrap_socket(raw, server_hostname=sni):
            return None
    except ssl.SSLCertVerificationError:
        return "tls ok, cert not valid for " + sni
    except socket.timeout:
        return "dropped after client hello"
    except ConnectionResetError:
        return "reset after client hello"
    except (OSError, ssl.SSLError) as e:
        return "tls " + short_err(e)
    finally:
        raw.close()


def check_server(addr, sni, timeout, ctx):
    host, port = split_hostport(addr, 443)
    t0 = time.monotonic()
    stop = tls_stage(host, port, sni or host, timeout, ctx)
    if stop:
        return Result("server", False, "%s:%d: %s" % (host, port, stop))
    return Result("server", True, "%s:%d tls ok, %d ms" % (host, port, (time.monotonic() - t0) * 1000))


def check_cdn(domain, ip, timeout, ctx):
    try:
        ip = ip or socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except OSError as e:
        return Result("cdn", False, "%s does not resolve (%s)" % (domain, short_err(e)))
    stop = tls_stage(ip, 443, domain, timeout, ctx)
    if stop:
        return Result("cdn", False, "%s: %s" % (domain, stop))
    try:
        status, body = https_get(ip, 443, domain, "/cdn-cgi/trace", timeout, ctx)
    except (OSError, ssl.SSLError) as e:
        return Result("cdn", False, "%s: tls ok, then %s" % (domain, short_err(e)))
    colo = dict(ln.split("=", 1) for ln in body.decode("latin-1").splitlines() if "=" in ln).get("colo")
    if status == 200 and colo:
        return Result("cdn", True, "%s: tls ok, colo %s" % (domain, colo))
    return Result("cdn", status in range(200, 500), "%s: tls ok, http %d, no trace" % (domain, status))


def check_tunnel(domain, resolvers, timeout):
    if not resolvers:
        return Result("tunnel", False, "no resolver known: add --resolver IP", skipped=True)
    last = ""
    for r in resolvers:
        host, port = split_hostport(r, 53)
        try:
            rcode, ans = udp_query(host, poll_name(domain), QTYPE_TXT, timeout, port=port)
        except OSError:
            last = "no answer via %s" % r
            continue
        if rcode == 0 and any(t == QTYPE_TXT for t, _ in ans):
            return Result("tunnel", True, "%s answers via %s" % (domain, r))
        last = "%s via %s" % (RCODES.get(rcode, "rcode %d" % rcode), r)
    return Result("tunnel", False, "%s: %s" % (domain, last))


# --- helpers -------------------------------------------------------------------

def split_hostport(s, default):
    if s.startswith("["):
        host, _, port = s[1:].partition("]")
        return host, int(port.lstrip(":") or default)
    if s.count(":") == 1:
        host, port = s.split(":")
        return host, int(port)
    return s, default


def short_err(e):
    if isinstance(e, socket.timeout):
        return "timeout"
    if isinstance(e, socket.gaierror):
        return "no answer" if e.errno in (getattr(socket, "EAI_AGAIN", -3),) else "not found"
    if isinstance(e, ConnectionResetError):
        return "reset"
    if isinstance(e, ConnectionRefusedError):
        return "refused"
    text = str(getattr(e, "reason", "") or e.__class__.__name__)
    return text.lower().replace("_", " ")[:28]


def read_targets(path):
    """(server, sni, cdn, cdn_ip, tunnel) from a file of links; the first of each kind wins."""
    server = sni = cdn = cdn_ip = tunnel = None
    with (sys.stdin if path == "-" else open(path, encoding="utf-8-sig")) as f:
        lines = [ln.strip() for ln in f]
    for ln in lines:
        if not ln or ln.startswith("#"):
            continue
        words = ln.split()
        if words[0] == "tunnel" and len(words) == 2:
            tunnel = tunnel or words[1]
            continue
        u = urlsplit(ln)
        if u.scheme not in ("vless", "trojan") or not u.hostname:
            continue
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        name = unquote(q.get("sni") or q.get("host") or "")
        port = u.port or 443
        if q.get("security") == "reality" and not server:
            server, sni = "%s:%d" % (u.hostname, port), name or None
        elif q.get("security", "tls" if u.scheme == "trojan" else "") == "tls" and not cdn:
            cdn = name or u.hostname
            cdn_ip = u.hostname if is_ip(u.hostname) and cdn != u.hostname else None
    return server, sni, cdn, cdn_ip, tunnel


def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def best_rung(res):
    ok = {r.name for r in res if r.ok and not r.skipped}
    if "server" in ok:
        return 1
    if "cdn" in ok:
        return 2
    if ok & {"doh", "dns-out"}:
        return 3
    if "tunnel" in ok or "dns" in ok:
        return 4
    return 5


def parse_args(argv=None):
    p = argparse.ArgumentParser(prog="kit-check", description="Which way out still works on this network.")
    p.add_argument("file", nargs="?", help="your own links: vless:// or trojan:// lines, `tunnel DOMAIN` lines")
    p.add_argument("--server", metavar="IP[:PORT]", help="your own server (REALITY / TLS), port 443 by default")
    p.add_argument("--sni", metavar="NAME", help="the SNI your server's config uses")
    p.add_argument("--cdn", metavar="DOMAIN", help="the domain of your config behind Cloudflare")
    p.add_argument("--cdn-ip", metavar="IP", help="a clean Cloudflare IP to use for --cdn")
    p.add_argument("--tunnel", metavar="DOMAIN", help="your DNS tunnel domain, e.g. t.example.com")
    p.add_argument("--resolver", metavar="IP[:PORT]", action="append", help="DNS server for --tunnel (default: the system's)")
    p.add_argument("--timeout", type=float, default=4.0, help="seconds per try (4)")
    p.add_argument("--insecure", action="store_true", help="don't verify certificates (your own test setups only)")
    p.add_argument("--version", action="version", version="kit-check " + VERSION)
    a = p.parse_args(argv)
    if a.sni and not a.server:
        p.error("--sni needs --server")
    if a.file:
        try:
            server, sni, cdn, cdn_ip, tunnel = read_targets(a.file)
        except OSError as e:
            p.error("can't read %s: %s" % (a.file, e.strerror))
        a.server, a.sni = a.server or server, a.sni or sni
        a.cdn, a.cdn_ip = a.cdn or cdn, a.cdn_ip or cdn_ip
        a.tunnel = a.tunnel or tunnel
    return a


def main(argv=None):
    a = parse_args(argv)
    ctx = ssl.create_default_context()
    if a.insecure:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    jobs = [check_dns, lambda: check_dns_out(a.timeout), lambda: check_doh(a.timeout, ctx)]
    if a.server:
        jobs.append(lambda: check_server(a.server, a.sni, a.timeout, ctx))
    if a.cdn:
        jobs.append(lambda: check_cdn(a.cdn, a.cdn_ip, a.timeout, ctx))
    if a.tunnel:
        jobs.append(lambda: check_tunnel(a.tunnel, a.resolver or system_resolvers(), a.timeout))
    with ThreadPoolExecutor(len(jobs)) as ex:
        res = list(ex.map(lambda f: f(), jobs))
    for r in res:
        print(r.line())
    rung = best_rung(res)
    print("rung %d of 5: %s" % (rung, RUNGS[rung]), flush=True)
    untested = [f for f, v in (("--server", a.server), ("--cdn", a.cdn), ("--tunnel", a.tunnel)) if not v]
    if untested and rung > 1:
        print("not tested: " + ", ".join(untested), file=sys.stderr)
    return 0 if rung < 5 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
