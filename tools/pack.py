"""Packing logic shared by tools/build-blocklist.sh and tools/test-pack.py.

The matcher (com.blockermod.core.matcher.BinarySearchDomainMatcher) matches a stored entry and
every one of its subdomains, so packing only needs the most comprehensive ancestor of each
domain: the parent is kept and every child it covers is dropped.

The old inline logic did the opposite (it dropped any domain that was itself a parent and kept
its children), which silently removed apex domains such as pornhub.com and left only www.*.
"""

import ipaddress

MAX_LABEL_LENGTH = 63
MAX_DOMAIN_LENGTH = 253

# Names reserved for local use (RFC 6761/6762/8375 and common LAN suffixes). They are never
# blocked, never packed into a list, and never rewritten (B1).
LOCAL_USE_SUFFIXES = (
    "localhost",
    "localdomain",
    "local",
    "home.arpa",
    "lan",
    "home",
    "internal",
    "test",
    "example",
    "invalid",
)


def is_address(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize(value):
    """Returns a packable domain, or None for addresses, junk and local-use names."""
    value = value.strip().lower().rstrip(".")
    if not value or is_address(value):
        return None
    if " " in value or "/" in value:
        return None
    if "." not in value:
        # Single-label names ("localhost", "broadcasthost") are local-use or junk (B1).
        return None
    try:
        value = value.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return None
    labels = value.split(".")
    if not labels or any(not label for label in labels):
        return None
    for label in labels:
        if len(label) > MAX_LABEL_LENGTH:
            return None
        if not all(character.isalnum() or character in "-_" for character in label):
            return None
    if len(value) > MAX_DOMAIN_LENGTH:
        return None
    if any(value == suffix or value.endswith("." + suffix) for suffix in LOCAL_USE_SUFFIXES):
        return None
    return value


def extract_domains(path):
    """Parses hosts-format lines (0.0.0.0 domain) and Adblock Plus rules (||domain^)."""
    domains = set()
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("!") or line.startswith("["):
                continue
            candidate = None
            if line.startswith("||"):
                # Adblock Plus: ||domain^  (optionally ||domain^$options)
                rule = line[2:].split("$", 1)[0]
                candidate = rule.split("^", 1)[0]
            else:
                fields = line.split()
                if len(fields) >= 2 and is_address(fields[0]):
                    candidate = fields[1]
                elif len(fields) == 1:
                    candidate = fields[0]
            if candidate:
                domain = normalize(candidate)
                if domain:
                    domains.add(domain)
    return domains


def proper_parents(domain):
    """Returns every ancestor of [domain], shortest first ("a.b.com" -> ["b.com", "com"])."""
    labels = domain.split(".")
    return [".".join(labels[i:]) for i in range(1, len(labels))]


def pack(domains):
    """Keeps parents, drops their covered children, packs reversed labels, returns (blob, count).

    Entries are sorted ascending by their bytes, exactly the order the matcher validates.
    """
    final = {d for d in domains if not any(p in domains for p in proper_parents(d))}

    entries = []
    for domain in final:
        labels = reversed(domain.split("."))
        entries.append("\u0000".join(labels).encode("ascii"))
    entries.sort()

    blob = bytearray()
    for entry in entries:
        blob += len(entry).to_bytes(2, "big")
        blob += entry
    return blob, len(entries)
