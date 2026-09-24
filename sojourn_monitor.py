#!/usr/bin/env python3

import json
import socket
import struct
import subprocess
import time
from collections import defaultdict

IPPROTO_TCP = 6
IPPROTO_UDP = 17

FLOW_ID_SIZE = 16
PKT_ID_SIZE = 20
SOJOURN_SAMPLE_SIZE = 24
SOJOURN_TS_MAP_MAX_ENTRIES = 65536

SOJOURN_SAMPLE_MAP = "/sys/fs/bpf/tc/globals/sojourn_sample_map"
INGRESS_COUNT_MAP = "/sys/fs/bpf/tc/globals/ingress_count_map"
EGRESS_COUNT_MAP = "/sys/fs/bpf/tc/globals/egress_count_map"
SOJOURN_DEBUG_MAP = "/sys/fs/bpf/tc/globals/sojourn_debug_map"

DEBUG_LABELS = {
    0: "egress_ipv4",
    1: "egress_udp",
    2: "udp_mark_ok",
    3: "udp_mark_bad",
    4: "record_packet",
    5: "ingress_ts_hit",
    6: "ingress_ts_miss",
    7: "sample_update",
}


def parse_hex_array(values):
    return bytes(int(value, 16) if isinstance(value, str) else value for value in values)


def dump_pinned_map(map_path):
    result = subprocess.run(
        ["bpftool", "map", "dump", "pinned", map_path, "-j"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return []
    return json.loads(result.stdout)


def parse_flow_id(key_bytes):
    if len(key_bytes) != FLOW_ID_SIZE:
        raise ValueError(f"unexpected flow_id size: {len(key_bytes)}")

    src_ip = socket.inet_ntoa(key_bytes[0:4])
    dst_ip = socket.inet_ntoa(key_bytes[4:8])
    src_port, dst_port = struct.unpack_from("=HH", key_bytes, 8)
    protocol = key_bytes[12]
    return src_ip, dst_ip, src_port, dst_port, protocol


def parse_pkt_id(key_bytes):
    if len(key_bytes) != PKT_ID_SIZE:
        raise ValueError(f"unexpected pkt_id size: {len(key_bytes)}")

    flow = parse_flow_id(key_bytes[:FLOW_ID_SIZE])
    packet_sequence, = struct.unpack_from("=I", key_bytes, FLOW_ID_SIZE)
    return (*flow, packet_sequence)


def fetch_sojourn_samples():
    samples = {}
    for entry in dump_pinned_map(SOJOURN_SAMPLE_MAP):
        key_bytes = parse_hex_array(entry["key"])
        value_bytes = parse_hex_array(entry["value"])
        if len(key_bytes) != PKT_ID_SIZE or len(value_bytes) != SOJOURN_SAMPLE_SIZE:
            continue

        packet = parse_pkt_id(key_bytes)
        samples[packet] = struct.unpack("=QQQ", value_bytes)
    return samples


def fetch_flow_counts(map_path):
    counts = {}
    for entry in dump_pinned_map(map_path):
        key_bytes = parse_hex_array(entry["key"])
        value_bytes = parse_hex_array(entry["value"])
        if len(key_bytes) != FLOW_ID_SIZE or len(value_bytes) != 8:
            continue

        flow = parse_flow_id(key_bytes)
        count, = struct.unpack("=Q", value_bytes)
        counts[flow] = count
    return counts


def fetch_debug_counters():
    counters = {}
    for entry in dump_pinned_map(SOJOURN_DEBUG_MAP):
        key_bytes = parse_hex_array(entry["key"])
        value_bytes = parse_hex_array(entry["value"])
        if len(key_bytes) != 4 or len(value_bytes) != 8:
            continue

        key, = struct.unpack("=I", key_bytes)
        value, = struct.unpack("=Q", value_bytes)
        counters[key] = value
    return counters


def protocol_name(protocol):
    if protocol == IPPROTO_TCP:
        return "TCP"
    if protocol == IPPROTO_UDP:
        return "UDP"
    return str(protocol)


def format_packet(packet):
    src_ip, dst_ip, src_port, dst_port, protocol, sequence = packet
    return (
        f"{protocol_name(protocol)} {src_ip}:{src_port} -> "
        f"{dst_ip}:{dst_port} | Seq: {sequence}"
    )


def format_flow(flow):
    src_ip, dst_ip, src_port, dst_port, protocol = flow
    return (
        f"{protocol_name(protocol)} {src_ip}:{src_port} -> "
        f"{dst_ip}:{dst_port}"
    )


def counter_delta(current_counts, baseline_counts, flow):
    current = int(current_counts.get(flow, 0))
    baseline = int(baseline_counts.get(flow, 0))
    return current if current < baseline else current - baseline


def flow_counter_deltas(ingress_counts, egress_counts,
                        ingress_baseline, egress_baseline, flow):
    ingress = counter_delta(ingress_counts, ingress_baseline, flow)
    egress = counter_delta(egress_counts, egress_baseline, flow)
    return ingress, egress, ingress - egress


def debug_summary(counters):
    if not counters:
        return ""
    return " | ".join(
        f"{DEBUG_LABELS[key]}={int(counters.get(key, 0))}"
        for key in sorted(DEBUG_LABELS)
    )


def print_counter_summary(ingress_counts, egress_counts,
                          ingress_baseline, egress_baseline, flow_stats):
    flows = set(flow_stats) | set(ingress_counts) | set(egress_counts)
    rows = []

    for flow in flows:
        ingress, egress, difference = flow_counter_deltas(
            ingress_counts,
            egress_counts,
            ingress_baseline,
            egress_baseline,
            flow,
        )
        if ingress or egress or flow in flow_stats:
            rows.append((flow, ingress, egress, difference))

    if not rows:
        print("\n[SUMMARY] No flow counter deltas observed.")
        return

    print("\n[SUMMARY] Counter deltas since monitor start:")
    for flow, ingress, egress, difference in sorted(rows):
        drop_rate = difference / ingress * 100.0 if ingress else 0.0
        print(
            f"[SUMMARY] {format_flow(flow)} | InDelta: {ingress} | "
            f"EgDelta: {egress} | DropDelta: {difference} | "
            f"DropRate: {drop_rate:.2f}%"
        )


def main():
    flow_stats = defaultdict(lambda: {"count": 0, "total_ns": 0, "max_ns": 0})
    seen_packets = set(fetch_sojourn_samples())
    ingress_baseline = fetch_flow_counts(INGRESS_COUNT_MAP)
    egress_baseline = fetch_flow_counts(EGRESS_COUNT_MAP)
    last_debug_print = 0.0

    print("Polling eBPF maps for Sojourn Time + In/Eg/Drop (Ctrl+C to stop)...", flush=True)
    print("Egress eBPF computes sojourn; Python prints completed samples.", flush=True)
    print("Counter baseline captured; start the traffic test now.", flush=True)

    try:
        while True:
            samples = fetch_sojourn_samples()
            ingress_counts = fetch_flow_counts(INGRESS_COUNT_MAP)
            egress_counts = fetch_flow_counts(EGRESS_COUNT_MAP)
            debug_counters = fetch_debug_counters()

            new_samples = [
                (packet, sample)
                for packet, sample in samples.items()
                if packet not in seen_packets
            ]
            new_samples.sort(key=lambda item: item[1][0])

            for packet, sample in new_samples:
                ingress_ts, egress_ts, sojourn_ns = sample
                if sojourn_ns == 0 or egress_ts <= ingress_ts:
                    seen_packets.add(packet)
                    continue

                flow = packet[:5]
                stats = flow_stats[flow]
                stats["count"] += 1
                stats["total_ns"] += sojourn_ns
                stats["max_ns"] = max(stats["max_ns"], sojourn_ns)

                mean_us = stats["total_ns"] / stats["count"] / 1000.0
                max_us = stats["max_ns"] / 1000.0
                ingress, egress, difference = flow_counter_deltas(
                    ingress_counts,
                    egress_counts,
                    ingress_baseline,
                    egress_baseline,
                    flow,
                )

                print(
                    f" {format_packet(packet)} "
                    f"InTS: {ingress_ts} ns | EgTS: {egress_ts} ns | "
                    f"Sojourn: {sojourn_ns / 1000.0:.2f} µs | "
                    f"Mean: {mean_us:.2f} µs | Max: {max_us:.2f} µs | "
                    f"In: {ingress} | Eg: {egress} | Drop: {difference}",
                    flush=True,
                )
                seen_packets.add(packet)

            if not new_samples and time.time() - last_debug_print >= 2.0:
                summary = debug_summary(debug_counters)
                if summary:
                    print(f"[DEBUG] No new sojourn samples yet | {summary}", flush=True)
                last_debug_print = time.time()

            if len(seen_packets) > SOJOURN_TS_MAP_MAX_ENTRIES:
                seen_packets &= set(samples)

            time.sleep(0.05)

    except KeyboardInterrupt:
        final_ingress = fetch_flow_counts(INGRESS_COUNT_MAP)
        final_egress = fetch_flow_counts(EGRESS_COUNT_MAP)
        print_counter_summary(
            final_ingress,
            final_egress,
            ingress_baseline,
            egress_baseline,
            flow_stats,
        )


if __name__ == "__main__":
    try:
        main()
    except FileNotFoundError:
        raise SystemExit("bpftool was not found in PATH")
    except json.JSONDecodeError as error:
        raise SystemExit(f"bpftool returned invalid JSON: {error}")
