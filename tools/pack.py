"""Packing logic shared by tools/build-blocklist.sh and tools/test-pack.py.

The matcher (com.blockermod.core.matcher.BinarySearchDomainMatcher) matches a stored entry and
every one of its subdomains, so packing only needs the most comprehensive ancestor of each
domain: the parent is kept and every child it covers is dropped.

The old inline logic did the opposite (it dropped any domain that was itself a parent and kept
its children), which silently removed apex domains such as pornhub.com and left only www.*.
"""

MAX_LABEL_LENGTH = 63
MAX_DOMAIN_LENGTH = 253


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
