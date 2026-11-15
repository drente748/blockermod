#!/usr/bin/env bash
#
# Build the safe search table used by the engine to rewrite queries.
#
# This script is a build time tool: the application never downloads anything. The table is written
# to app/src/main/assets/safesearch.json and read as it is.
#
# Sources, and only these:
#   S1  Google: every entry of the committed snapshot tools/supported-domains-google.txt becomes
#       the exact host www.<domain> and is rewritten to forcesafesearch.google.com.
#   S2  Bing: www.bing.com and edgeservices.bing.com become strict.bing.com.
#   S3  DuckDuckGo: duckduckgo.com and www.duckduckgo.com become safe.duckduckgo.com.
#   S4  Brave: search.brave.com becomes forcesafe.search.brave.com.
#   S5  YouTube: www.youtube.com, m.youtube.com, youtubei.googleapis.com, youtube.googleapis.com and
#       www.youtube-nocookie.com become restrict.youtube.com.
#
# Nothing else is added: an entry that is not listed here is never rewritten.
#
# The output is a JSON object with the metadata of the build and the exact host to target map.
# The same snapshot always produces the same file.
#
# Exit codes:
#   0  success
#   1  a source could not be read
#   2  the license of a source is not cleared
#   3  the snapshot could not be parsed
#
# Usage:
#   tools/build-safesearch.sh [--snapshot FILE] [--output FILE]

set -euo pipefail

EXIT_OK=0
EXIT_FETCH=1
EXIT_LICENSE=2
EXIT_PARSE=3

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

SNAPSHOT="${SCRIPT_DIR}/supported-domains-google.txt"
OUTPUT="${PROJECT_DIR}/app/src/main/assets/safesearch.json"

usage() {
    sed -n '2,32p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --snapshot)
            SNAPSHOT="$2"
            shift 2
            ;;
        --output)
            OUTPUT="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit "${EXIT_OK}"
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit "${EXIT_PARSE}"
            ;;
    esac
done

if [ ! -f "${SNAPSHOT}" ]; then
    echo "the Google supported domains snapshot is missing: ${SNAPSHOT}" >&2
    exit "${EXIT_FETCH}"
fi

PYTHON=""
for candidate in python3 python; do
    if command -v "${candidate}" >/dev/null 2>&1; then
        PYTHON="${candidate}"
        break
    fi
done

if [ -z "${PYTHON}" ]; then
    echo "python3 is required to build the safe search table" >&2
    exit "${EXIT_PARSE}"
fi

mkdir -p "$(dirname "${OUTPUT}")"

"${PYTHON}" - "${SNAPSHOT}" "${OUTPUT}" <<'PY'
import json
import sys

snapshot_path = sys.argv[1]
output_path = sys.argv[2]

FORCESAFE_GOOGLE = "forcesafesearch.google.com"
STRICT_BING = "strict.bing.com"
SAFE_DUCKDUCKGO = "safe.duckduckgo.com"
FORCESAFE_BRAVE = "forcesafe.search.brave.com"
RESTRICT_YOUTUBE = "restrict.youtube.com"

entries = {}
google_domains = []

with open(snapshot_path, "r", encoding="utf-8") as handle:
    for raw in handle:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        domain = line.lstrip(".").strip().lower()
        if not domain or "." not in domain:
            continue
        google_domains.append(domain)

for domain in google_domains:
    entries["www." + domain] = FORCESAFE_GOOGLE

for host in ("www.bing.com", "edgeservices.bing.com"):
    entries[host] = STRICT_BING

for host in ("duckduckgo.com", "www.duckduckgo.com"):
    entries[host] = SAFE_DUCKDUCKGO

entries["search.brave.com"] = FORCESAFE_BRAVE

for host in (
    "www.youtube.com",
    "m.youtube.com",
    "youtubei.googleapis.com",
    "youtube.googleapis.com",
    "www.youtube-nocookie.com",
):
    entries[host] = RESTRICT_YOUTUBE

payload = {
    "sources": [
        "google-supported-domains",
        "bing",
        "duckduckgo",
        "brave",
        "youtube",
    ],
    "count": len(entries),
    "entries": dict(sorted(entries.items())),
}

with open(output_path, "w", encoding="utf-8", newline="\n") as handle:
    json.dump(payload, handle, indent=2, sort_keys=False)
    handle.write("\n")

print("entries:", len(entries))
PY

echo "wrote ${OUTPUT}" >&2
exit "${EXIT_OK}"
