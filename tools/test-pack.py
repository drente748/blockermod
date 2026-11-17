#!/usr/bin/env python3
"""Standalone regression test for the packed blocklist logic (A2).

The old inline logic in build-blocklist.sh dropped any domain that was itself a parent and kept
its children, which silently removed apex domains (pornhub.com) and kept only www.*. The fixed
logic in pack.py keeps the most comprehensive parent and drops covered children.

Usage: python3 tools/test-pack.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pack import pack, proper_parents, normalize, extract_domains, LOCAL_USE_SUFFIXES

failures = []


def check(name, condition, detail=""):
    if condition:
        print("PASS " + name)
    else:
        failures.append(name)
        print("FAIL " + name + (" -- " + detail if detail else ""))


def unpack(blob, count):
    """Decodes the packed format back to a domain set; asserts size and sort order."""
    domains = []
    offset = 0
    while offset < len(blob):
        length = int.from_bytes(blob[offset:offset + 2], "big")
        entry = blob[offset + 2:offset + 2 + length].decode("ascii")
        domains.append(".".join(reversed(entry.split("\u0000"))))
        offset += 2 + length
    check("packed count matches header", len(domains) == count, "%d != %d" % (len(domains), count))
    check("packed entries are sorted and unique", domains == sorted(set(domains)))
    return set(domains)


# The exact acceptance cases from the fix spec.
result = pack({"example.com", "ads.example.com"})
check("parent kept, child dropped", unpack(*result) == {"example.com"})

result = pack({"a.b.example.com", "b.example.com", "example.com"})
check("chain collapses to the apex", unpack(*result) == {"example.com"})

result = pack({"example.com", "other.com"})
check("unrelated domains both kept", unpack(*result) == {"example.com", "other.com"})

# The apex/child case that motivated the fix.
result = pack({"pornhub.com", "www.pornhub.com"})
domains = unpack(*result)
check("apex survives packing", domains == {"pornhub.com"}, str(domains))

# The matcher covers subdomains, so the apex entry must block every child.
check("proper_parents of a bare TLD-free domain", proper_parents("pornhub.com") == ["com"])
check("proper_parents of a deep domain",
      proper_parents("a.b.example.com") == ["b.example.com", "example.com", "com"])

# A parent that is not in the set must not remove its children.
result = pack({"ads.example.com", "tracker.example.net"})
domains = unpack(*result)
check("uncovered children stay", domains == {"ads.example.com", "tracker.example.net"}, str(domains))

# Local-use names must never enter a packed list (B1).
check("single label rejected", normalize("localhost") is None)
check("single label broadcasthost rejected", normalize("broadcasthost") is None)
check("localhost.localdomain rejected", normalize("localhost.localdomain") is None)
check("ip6-localhost rejected", normalize("ip6-localhost") is None)
check("foo.localhost rejected", normalize("foo.localhost") is None)
check("foo.local rejected", normalize("foo.local") is None)
check("lan suffix rejected", normalize("nas.lan") is None)
check("home.arpa suffix rejected", normalize("router.home.arpa") is None)
for suffix in LOCAL_USE_SUFFIXES:
    check("suffix %s itself rejected" % suffix, normalize(suffix) is None)
check("ordinary domain survives", normalize("Example.COM.") == "example.com")
check("address rejected", normalize("127.0.0.1") is None)

# A standard hosts header must produce no entries (B1).
hosts_lines = "\n".join([
    "127.0.0.1 localhost",
    "127.0.0.1 localhost.localdomain",
    "255.255.255.255 broadcasthost",
    "::1 ip6-localhost ip6-loopback",
    "fe00::0 ip6-localnet",
    "0.0.0.0 ads.example.com",
])
hosts_path = os.path.join(os.environ.get("TEMP", "/tmp"), "test-pack-hosts")
with open(hosts_path, "w", encoding="utf-8") as handle:
    handle.write(hosts_lines)
domains = extract_domains(hosts_path)
os.remove(hosts_path)
check("standard hosts lines yield only real domains", domains == {"ads.example.com"}, str(domains))

print()
if failures:
    print("%d failure(s): %s" % (len(failures), ", ".join(failures)))
    sys.exit(1)
print("all pack regression tests passed")
