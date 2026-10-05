#!/usr/bin/env bash
set -euo pipefail

# Usage: BPF_MAP_API=legacy ./deploy_cls.sh [interface]
IFACE="${1:-eth0}"
BPF_MAP_API="${BPF_MAP_API:-legacy}"
ENABLE_DST_PRIORITY="${ENABLE_DST_PRIORITY:-1}"

case "$BPF_MAP_API" in
    legacy)
        MAP_CFLAGS=(-DBPF_MAP_LEGACY)
        ;;
    libbpf)
        MAP_CFLAGS=()
        ;;
    *)
        echo "ERROR: BPF_MAP_API must be 'legacy' or 'libbpf'." >&2
        exit 2
        ;;
esac

case "$ENABLE_DST_PRIORITY" in
    0|1) ;;
    *)
        echo "ERROR: ENABLE_DST_PRIORITY must be 0 or 1." >&2
        exit 2
        ;;
esac

echo "Interface   : $IFACE"
echo "BPF map API: $BPF_MAP_API"
echo "DST priority: $ENABLE_DST_PRIORITY"

echo "[1/5] Compiling eBPF programs..."
clang -O2 -g -target bpf -Wall -Wextra "${MAP_CFLAGS[@]}" \
    -DENABLE_IFB_REDIRECT=0 \
    -DENABLE_DST_PRIORITY="$ENABLE_DST_PRIORITY" \
    -c cls_dt_ingress.c -o cls_dt_ingress.o
clang -O2 -g -target bpf -Wall -Wextra "${MAP_CFLAGS[@]}" \
    -c cls_dt_egress.c -o cls_dt_egress.o

echo "[2/5] Ensuring bpffs is mounted..."
sudo mkdir -p /sys/fs/bpf
mountpoint -q /sys/fs/bpf || sudo mount -t bpf bpf /sys/fs/bpf
sudo mkdir -p /sys/fs/bpf/tc/globals

echo "[3/5] Removing maps from previous layouts..."
for map_name in \
    ingress_ts_map egress_ts_map sojourn_sample_map \
    ingress_count_map egress_count_map udp_seq_map \
    sojourn_stats_map sojourn_debug_map ifb_ifindex_map; do
    sudo rm -f "/sys/fs/bpf/tc/globals/$map_name"
done

echo "[4/5] Replacing TC hooks..."
sudo tc qdisc replace dev "$IFACE" clsact
sudo tc filter replace dev "$IFACE" ingress \
    bpf da obj cls_dt_ingress.o sec classifier
sudo tc filter replace dev "$IFACE" egress \
    bpf da obj cls_dt_egress.o sec egress

echo "[5/5] Deployment complete."
echo "Monitor: sudo ./sojourn_monitor.py"
echo "Filters: tc -s filter show dev $IFACE ingress"
echo "         tc -s filter show dev $IFACE egress"
