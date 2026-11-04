#!/usr/bin/env python3
"""
nla_replay.py: check a captured NLA logon offline, from MS-NLMP alone.

  nla_replay.py DUMP PASSWORDFILE [USER] [DOMAIN]

DUMP is RDPProbe DUMP=file output: lines "C>S n <hex>" / "S>C n <hex>",
the TSRequests up to the AUTHENTICATE and the server's answer.
PASSWORDFILE holds the password (no newline needed); it is never printed.

Recomputes, independently of gfopenntlm, NTOWFv2 / NTProofStr
([MS-NLMP] 3.3.2), the KeyExchangeKey and ExportedSessionKey (3.4.5.1,
3.1.5.1.2) and the MIC over NEGOTIATE | CHALLENGE | AUTHENTICATE with
the MIC zeroed (3.1.5.1.2), and compares them with what the client sent.
Prints only matches and mismatches and the message fields, no secrets.

MIT, Copyright (c) 2026 AmiCradle Team. Written by Sacredtrees (Team 6).
"""
import hashlib, hmac, struct, sys

def md4(m):
    # RFC 1320
    def F(x, y, z): return (x & y) | (~x & z)
    def G(x, y, z): return (x & y) | (x & z) | (y & z)
    def H(x, y, z): return x ^ y ^ z
    def rol(v, s): v &= 0xffffffff; return ((v << s) | (v >> (32 - s))) & 0xffffffff
    ml = len(m) * 8
    m = m + b"\x80" + b"\x00" * ((55 - len(m)) % 64) + struct.pack("<Q", ml)
    a, b, c, d = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    for o in range(0, len(m), 64):
        X = struct.unpack("<16I", m[o:o + 64]); A, B, C, D = a, b, c, d
        for i in (0, 4, 8, 12):
            a = rol(a + F(b, c, d) + X[i], 3); d = rol(d + F(a, b, c) + X[i + 1], 7)
            c = rol(c + F(d, a, b) + X[i + 2], 11); b = rol(b + F(c, d, a) + X[i + 3], 19)
        for i in (0, 1, 2, 3):
            a = rol(a + G(b, c, d) + X[i] + 0x5a827999, 3); d = rol(d + G(a, b, c) + X[i + 4] + 0x5a827999, 5)
            c = rol(c + G(d, a, b) + X[i + 8] + 0x5a827999, 9); b = rol(b + G(c, d, a) + X[i + 12] + 0x5a827999, 13)
        for i in (0, 2, 1, 3):
            a = rol(a + H(b, c, d) + X[i] + 0x6ed9eba1, 3); d = rol(d + H(a, b, c) + X[i + 8] + 0x6ed9eba1, 9)
            c = rol(c + H(d, a, b) + X[i + 4] + 0x6ed9eba1, 11); b = rol(b + H(c, d, a) + X[i + 12] + 0x6ed9eba1, 15)
        a, b, c, d = (a + A) & 0xffffffff, (b + B) & 0xffffffff, (c + C) & 0xffffffff, (d + D) & 0xffffffff
    return struct.pack("<4I", a, b, c, d)

def rc4(key, data):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 255; S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray()
    for ch in data:
        i = (i + 1) & 255; j = (j + S[i]) & 255; S[i], S[j] = S[j], S[i]
        out.append(ch ^ S[(S[i] + S[j]) & 255])
    return bytes(out)

def hm(k, m): return hmac.new(k, m, hashlib.md5).digest()

def der(b, o):
    tag = b[o]; l = b[o + 1]; o += 2
    if l & 0x80:
        n = l & 0x7f; l = int.from_bytes(b[o:o + n], "big"); o += n
    return tag, b[o:o + l], o + l

def children(b):
    o = 0
    while o < len(b):
        t, v, o = der(b, o); yield t, v

def tsrequest(b):
    t, body, _ = der(b, 0); r = {}
    for tag, v in children(body):
        n = tag & 0x1f; inner = der(v, 0)
        if n == 1:  # negoTokens SEQUENCE OF SEQUENCE { [0] OCTET STRING }
            seq = inner[1]; _, item, _ = der(seq, 0); _, x, _ = der(item, 0); r["nego"] = der(x, 0)[1]
        elif n == 0 or n == 4:
            r[n] = int.from_bytes(inner[1], "big")
        else:
            r[n] = inner[1]
    return r

def field(m, o):
    l, _, off = struct.unpack_from("<HHI", m, o); return m[off:off + l]

AVN = {0: "MsvAvEOL", 1: "MsvAvNbComputerName", 2: "MsvAvNbDomainName", 3: "MsvAvDnsComputerName",
       4: "MsvAvDnsDomainName", 5: "MsvAvDnsTreeName", 6: "MsvAvFlags", 7: "MsvAvTimestamp",
       8: "MsvAvSingleHost", 9: "MsvAvTargetName", 10: "MsvAvChannelBindings"}

def avpairs(ti):
    o = 0; out = []
    while o + 4 <= len(ti):
        i, l = struct.unpack_from("<HH", ti, o); v = ti[o + 4:o + 4 + l]; o += 4 + l
        out.append((i, v))
        if i == 0: break
    return out, ti[o:]

def show_av(prefix, pairs):
    for i, v in pairs:
        s = v.decode("utf-16le", "replace") if i in (1, 2, 3, 4, 5, 9) else v.hex()
        print("%s %s(%d) len %d: %s" % (prefix, AVN.get(i, "?"), i, len(v), s))

def main():
    if len(sys.argv) < 3:
        print(__doc__); return 2
    lines = {}
    for ln in open(sys.argv[1]):
        p = ln.split()
        if len(p) == 3: lines[(p[0], int(p[1]))] = bytes.fromhex(p[2])
    pw = open(sys.argv[2], "rb").read().rstrip(b"\r\n").decode("utf-8")
    t1, t2, t3 = tsrequest(lines[("C>S", 1)]), tsrequest(lines[("S>C", 1)]), tsrequest(lines[("C>S", 2)])
    neg, chal, auth = t1["nego"], t2["nego"], t3["nego"]
    print("TSRequest versions: client %s, server %s" % (t1.get(0), t2.get(0)))
    print("NEGOTIATE %d bytes, flags 0x%08x" % (len(neg), struct.unpack_from("<I", neg, 12)[0]))
    cf = struct.unpack_from("<I", chal, 20)[0]
    print("CHALLENGE %d bytes, flags 0x%08x, TargetName %r, Version %s" % (len(chal), cf,
          field(chal, 12).decode("utf-16le", "replace"), chal[48:56].hex() if len(chal) >= 56 else "-"))
    sc = chal[24:32]
    cav, rest = avpairs(field(chal, 40)); show_av("  CHALLENGE", cav)
    if rest: print("  CHALLENGE TargetInfo has %d bytes after MsvAvEOL" % len(rest))
    af = struct.unpack_from("<I", auth, 60)[0]
    lm, nt, dom, user, ws, ekey = (field(auth, o) for o in (12, 20, 28, 36, 44, 52))
    print("AUTHENTICATE %d bytes, flags 0x%08x, Version %s" % (len(auth), af, auth[64:72].hex()))
    print("  user %r domain %r workstation %r, LM %d bytes (%s), NT %d bytes, key %d bytes" % (
          user.decode("utf-16le"), dom.decode("utf-16le"), ws.decode("utf-16le"), len(lm),
          "Z(24)" if lm == b"\0" * 24 else "not zero", len(nt), len(ekey)))
    proof, blob = nt[:16], nt[16:]
    aav, tail = avpairs(blob[28:]); show_av("  AUTHENTICATE", aav)
    print("  blob time %s, client challenge (not secret) %s, %d bytes after MsvAvEOL" % (blob[8:16].hex(), blob[16:24].hex(), len(tail)))
    ctime = [v for i, v in cav if i == 7]; atime = [v for i, v in aav if i == 7]
    print("  timestamp: blob %s the CHALLENGE's MsvAvTimestamp" % ("equals" if ctime and blob[8:16] == ctime[0] else "DIFFERS FROM"))
    uname = sys.argv[3] if len(sys.argv) > 3 else user.decode("utf-16le")
    dname = sys.argv[4] if len(sys.argv) > 4 else dom.decode("utf-16le")
    ntowf = hm(md4(pw.encode("utf-16le")), (uname.upper() + dname).encode("utf-16le"))
    want = hm(ntowf, sc + blob)
    print("NTProofStr: %s (for user %r, domain %r)" % ("MATCHES" if want == proof else "DIFFERS", uname, dname))
    sbk = hm(ntowf, proof)
    exported = rc4(sbk, ekey) if af & 0x40000000 else sbk
    mic = auth[72:88]; z = auth[:72] + b"\0" * 16 + auth[88:]
    want_mic = hm(exported, neg + chal + z)
    print("MIC at offset 72: %s" % ("MATCHES" if want_mic == mic else "DIFFERS"))
    if 2 in t2 or ("S>C", 2) in lines:
        r = tsrequest(lines[("S>C", 2)]) if ("S>C", 2) in lines else {}
        if 4 in r: print("server's answer: errorCode 0x%08X" % r[4])
        elif 3 in r: print("server's answer: pubKeyAuth (%d bytes): the server accepted the AUTHENTICATE" % len(r[3]))
    return 0

if __name__ == "__main__":
    sys.exit(main())
