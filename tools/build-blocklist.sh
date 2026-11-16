#!/usr/bin/env bash
#
# Build the blocklist binary from pinned public sources.
#
# This script is a build time tool: the application never downloads anything and reads the
# generated file as it is. The output format is the one read by
# com.blockermod.core.matcher.BinarySearchDomainMatcher:
#
#   repeated records of [length:2 big endian][entry bytes]
#   entry bytes = the reversed labels of the domain joined by a zero byte
#                 ("ads.example.com" becomes "com\0example\0ads")
#   the records are sorted ascending by their bytes
#
# The file is therefore usable as it is: the matcher searches the bytes, it never parses them.
#
# Pipeline:
#   fetch (pinned by commit and checksum) -> parse -> normalize -> drop addresses and invalid
#   names -> deduplicate -> drop the names already covered by a parent -> remove the protected
#   names -> remove the safe search hosts -> sort by reversed labels -> write the binary and the
#   metadata file.
#
# The same sources always produce the same binary.
#
# Exit codes:
#   0  success
#   1  a source could not be fetched, or its checksum did not match
#   2  the license of a source is not cleared; the gate stops before any download
#   3  a source could not be parsed
#
# Usage:
#   tools/build-blocklist.sh [--offline] [--manifest FILE] [--output DIR] [--cache DIR]

set -euo pipefail

EXIT_OK=0
EXIT_FETCH=1
EXIT_LICENSE=2
EXIT_PARSE=3

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

MANIFEST="${SCRIPT_DIR}/sources.tsv"
CACHE_DIR="${SCRIPT_DIR}/cache"
OUTPUT_DIR="${PROJECT_DIR}/app/src/main/assets"
ALLOWLIST="${SCRIPT_DIR}/allowlist.txt"
SAFESEARCH_HOSTS="${SCRIPT_DIR}/safesearch-hosts.txt"
OFFLINE=0

usage() {
    sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --offline)
            OFFLINE=1
            shift
            ;;
        --manifest)
            MANIFEST="$2"
            shift 2
            ;;
        --output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --cache)
            CACHE_DIR="$2"
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

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required to build the blocklist" >&2
    exit "${EXIT_PARSE}"
fi

# ---------------------------------------------------------------------------
# License gate: no source is downloaded before its license is cleared.
# ---------------------------------------------------------------------------

gate_licenses() {
    local blocked=0
    local name url commit sha license decision approver date category

    while IFS=$'\t' read -r name url commit sha license decision approver date category || [ -n "${name:-}" ]; do
        [ -z "${name:-}" ] && continue
        case "${name}" in \#*|name) continue ;; esac

        if [ "${decision:-}" != "auto-allowed" ]; then
            echo "license not cleared for ${name} (${url})" >&2
            blocked=1
            continue
        fi
        if [ -z "${license:-}" ]; then
            echo "no license file recorded for ${name}" >&2
            blocked=1
        fi
    done < "${MANIFEST}"

    return "${blocked}"
}

if ! gate_licenses; then
    echo "the license gate stops the build before any download" >&2
    echo "clear the sources in ${MANIFEST} and in docs/LICENSE_DECISIONS.md first" >&2
    exit "${EXIT_LICENSE}"
fi

# ---------------------------------------------------------------------------
# Fetch with a pinned commit and a pinned checksum.
# ---------------------------------------------------------------------------

verify_checksum() {
    local file="$1"
    local expected="$2"
    local actual

    if [ -z "${expected}" ] || [ "${expected}" = "TBD" ]; then
        echo "no checksum pinned for ${file}" >&2
        return 1
    fi

    actual="$(sha256sum "${file}" | cut -d' ' -f1)"
    [ "${actual}" = "${expected}" ]
}

fetch_source() {
    local name="$1"
    local url="$2"
    local commit="$3"
    local sha="$4"
    local file="${CACHE_DIR}/${name}@${commit}"

    mkdir -p "${CACHE_DIR}"

    if [ -f "${file}" ]; then
        if verify_checksum "${file}" "${sha}"; then
            echo "using the cached copy of ${name}" >&2
            printf '%s' "${file}"
            return 0
        fi
        echo "the cached copy of ${name} does not match its checksum" >&2
        return 1
    fi

    if [ "${OFFLINE}" -eq 1 ]; then
        echo "offline mode and ${name} is not cached" >&2
        return 1
    fi

    echo "fetching ${name}" >&2
    if ! curl --fail --location --silent --show-error --retry 3 \
        --output "${file}.part" "${url}"; then
        rm -f "${file}.part"
        echo "could not fetch ${name}" >&2
        return 1
    fi

    if ! verify_checksum "${file}.part" "${sha}"; then
        rm -f "${file}.part"
        echo "the checksum of ${name} does not match the pinned value" >&2
        return 1
    fi

    mv "${file}.part" "${file}"
    printf '%s' "${file}"
}

CACHED_FILES=()
SOURCE_NAMES=()
CATEGORIES=()

while IFS=$'\t' read -r name url commit sha license decision approver date category || [ -n "${name:-}" ]; do
    [ -z "${name:-}" ] && continue
    case "${name}" in \#*|name) continue ;; esac

    file="$(fetch_source "${name}" "${url}" "${commit}" "${sha}")" || exit "${EXIT_FETCH}"
    CACHED_FILES+=("${file}")
    SOURCE_NAMES+=("${name}")
    CATEGORIES+=("${category}")
done < "${MANIFEST}"

if [ "${#CACHED_FILES[@]}" -eq 0 ]; then
    echo "the manifest holds no source" >&2
    exit "${EXIT_PARSE}"
fi

# ---------------------------------------------------------------------------
# Transform and pack.
# ---------------------------------------------------------------------------

mkdir -p "${OUTPUT_DIR}"

PACK_RESULT="$(python3 - "${OUTPUT_DIR}" "${ALLOWLIST}" "${SAFESEARCH_HOSTS}" "${#CACHED_FILES[@]}" "${CATEGORIES[@]}" "${CACHED_FILES[@]}" <<'PY'
import ipaddress
import json
import os
import sys

output_dir = sys.argv[1]
allowlist_path = sys.argv[2]
safesearch_path = sys.argv[3]
source_count = int(sys.argv[4])
categories = sys.argv[5:5 + source_count]
source_paths = sys.argv[5 + source_count:]


def read_list(path):
    values = set()
    if not os.path.exists(path):
        return values
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            values.add(line.lower().rstrip("."))
    return values


def is_address(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize(value):
    value = value.strip().lower().rstrip(".")
    if not value or is_address(value):
        return None
    if " " in value or "/" in value:
        return None
    try:
        value = value.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return None
    labels = value.split(".")
    if not labels or any(not label for label in labels):
        return None
    for label in labels:
        if len(label) > 63:
            return None
        if not all(character.isalnum() or character in "-_" for character in label):
            return None
    if len(value) > 253:
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


def pack(domains):
    """Drops child domains covered by a parent, packs reversed labels, returns (blob, count)."""
    parents = set()
    for domain in domains:
        labels = domain.split(".")
        for index in range(1, len(labels)):
            parents.add(".".join(labels[index:]))
    final = {domain for domain in domains if domain not in parents}

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


protected = read_list(allowlist_path) | read_list(safesearch_path)

# Collect domains per category.
per_category = {"adult": set(), "bypass": set(), "unsupported": set()}
for category, path in zip(categories, source_paths):
    bucket = per_category.get(category)
    if bucket is None:
        print("unknown category: " + category, file=sys.stderr)
        sys.exit(3)
    bucket |= extract_domains(path)

# Protected domains are never blocked, in any list.
for bucket in per_category.values():
    bucket.difference_update(protected)

result = {}
for category, bucket in per_category.items():
    name = {"adult": "blocklist", "bypass": "bypass", "unsupported": "unsupported"}[category]
    blob, count = pack(bucket)
    with open(os.path.join(output_dir, name + ".bin"), "wb") as handle:
        handle.write(blob)
    result[name] = {"count": count, "bytes": len(blob)}

print(json.dumps(result))
PY
)" || exit "${EXIT_PARSE}"

COUNTS_JSON="${PACK_RESULT}"

write_meta() {
    local name="$1" out="$2"
    local count hash sources_json
    count="$(printf '%s' "${COUNTS_JSON}" | python3 -c "import json,sys; print(json.load(sys.stdin)['${name}']['count'])")"
    hash="$(sha256sum "${OUTPUT_DIR}/${out}.bin" | cut -d' ' -f1)"
    sources_json="$(printf '%s\n' "${SOURCE_NAMES[@]}" | python3 -c 'import json,sys; print(json.dumps([line.strip() for line in sys.stdin if line.strip()]))')"
    cat > "${OUTPUT_DIR}/${out}.meta" <<META
{
  "sources": ${sources_json},
  "count": ${count},
  "hash": "${hash}"
}
META
    echo "wrote ${OUTPUT_DIR}/${out}.bin with ${count} entries" >&2
    echo "sha256 ${hash}" >&2
}

write_meta blocklist blocklist
write_meta bypass bypass
write_meta unsupported unsupported
exit "${EXIT_OK}"
