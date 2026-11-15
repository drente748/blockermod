#!/usr/bin/env bash
#
# Measurement harness for the blocking engine.
#
# It drives a connected device through adb and writes a report to the given directory.
# Nothing here is part of the application: it only observes it.
#
# Measurements:
#   idle        forces device idle and samples the battery level over a window
#   latency     sends DNS queries from the device and reports the lookup percentiles
#   load        sends a burst of DNS queries and reports the memory and the cpu of the app
#   all         runs the three measurements in order
#
# Usage:
#   tools/perf-measure.sh [idle|latency|load|all] [--package com.blockermod] [--output DIR]
#                        [--window 3600] [--queries 1000]

set -euo pipefail

PACKAGE="com.blockermod"
OUTPUT_DIR="${PWD}/build/perf"
MODE="all"
IDLE_WINDOW=3600
QUERY_COUNT=1000

ADB="${ADB:-adb}"

usage() {
    sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        idle|latency|load|all)
            MODE="$1"
            shift
            ;;
        --package)
            PACKAGE="$2"
            shift 2
            ;;
        --output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --window)
            IDLE_WINDOW="$2"
            shift 2
            ;;
        --queries)
            QUERY_COUNT="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if ! command -v "${ADB}" >/dev/null 2>&1; then
    echo "adb is required" >&2
    exit 1
fi

if ! "${ADB}" get-state >/dev/null 2>&1; then
    echo "no device is connected" >&2
    exit 1
fi

mkdir -p "${OUTPUT_DIR}"
REPORT="${OUTPUT_DIR}/perf-report.txt"

device_battery_level() {
    "${ADB}" shell dumpsys battery | sed -n 's/^ *level: *\([0-9]*\).*/\1/p' | head -n 1
}

measure_idle() {
    echo "== idle ==" | tee -a "${REPORT}"
    "${ADB}" shell dumpsys deviceidle force-idle >/dev/null 2>&1 || true
    local start end
    start="$(device_battery_level)"
    echo "battery at the start: ${start}" | tee -a "${REPORT}"
    sleep "${IDLE_WINDOW}"
    end="$(device_battery_level)"
    echo "battery at the end: ${end} (window ${IDLE_WINDOW}s)" | tee -a "${REPORT}"
    "${ADB}" shell dumpsys deviceidle unforce >/dev/null 2>&1 || true
}

measure_latency() {
    echo "== latency ==" | tee -a "${REPORT}"
    local count=100
    "${ADB}" shell "for i in \$(seq 1 ${count}); do \
        t0=\$(date +%s%N); \
        nslookup example.com >/dev/null 2>&1; \
        t1=\$(date +%s%N); \
        echo \$(( (t1 - t0) / 1000000 )); \
        done" > "${OUTPUT_DIR}/latency.txt"
    "${ADB}" pull "${OUTPUT_DIR}/latency.txt" >/dev/null 2>&1 || true
    python3 - "${OUTPUT_DIR}/latency.txt" <<'PY' | tee -a "${REPORT}"
import sys

values = []
with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as handle:
    for line in handle:
        line = line.strip()
        if line.isdigit():
            values.append(int(line))

if not values:
    print("no sample collected")
    raise SystemExit(0)

values.sort()


def percentile(fraction):
    index = min(len(values) - 1, int(round(fraction * (len(values) - 1))))
    return values[index]


print("samples:", len(values))
print("min ms:", values[0])
print("p50 ms:", percentile(0.50))
print("p95 ms:", percentile(0.95))
print("p99 ms:", percentile(0.99))
print("max ms:", values[-1])
PY
}

measure_load() {
    echo "== load ==" | tee -a "${REPORT}"
    "${ADB}" shell "for i in \$(seq 1 ${QUERY_COUNT}); do \
        nslookup load-\$i.example.com >/dev/null 2>&1; \
        done" >/dev/null
    "${ADB}" shell dumpsys meminfo "${PACKAGE}" | sed -n '1,40p' >> "${REPORT}"
    "${ADB}" shell top -b -n 1 -o PID,%CPU,RES,ARGS 2>/dev/null | grep -i "${PACKAGE}" >> "${REPORT}" || true
    "${ADB}" shell dumpsys cpuinfo | sed -n '1,40p' >> "${REPORT}" || true
}

case "${MODE}" in
    idle)
        measure_idle
        ;;
    latency)
        measure_latency
        ;;
    load)
        measure_load
        ;;
    all)
        measure_latency
        measure_load
        measure_idle
        ;;
esac

echo "report written to ${REPORT}" >&2
