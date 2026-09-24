# eBPF Traffic Classifier

This project uses Linux Traffic Control (TC) eBPF programs to classify IPv4
TCP/UDP flows and measure packet sojourn time between ingress and egress.

The current classifier keeps destination-IP priority as a reproducible baseline:

```text
priority destination -> PRIO class 1:1
other destinations   -> PRIO class 1:3
```

Decision Tree classification is developed separately and can replace this
baseline after its runtime features have been validated.

## Requirements

On Ubuntu/Debian:

```bash
sudo apt update
sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r) iproute2 bpftool
```

The IFB experiment also requires IFB kernel support:

```bash
sudo modprobe ifb
```

## Build

The same source supports legacy iproute2 map definitions and modern BTF/libbpf
map definitions.

```bash
# Legacy tc ELF map definitions (default)
make BPF_MAP_API=legacy

# BTF/libbpf map definitions
make clean
make BPF_MAP_API=libbpf
```

Build ingress with IFB redirect support:

```bash
make clean
make BPF_MAP_API=legacy ENABLE_IFB_REDIRECT=1
```

## Local Deployment

```bash
BPF_MAP_API=legacy ./deploy_cls.sh eth0
sudo ./sojourn_monitor.py
```

The selected loader must support the chosen map declaration format. Use
`legacy` with older `tc` ELF loaders. Use `libbpf` only with a loader that
supports BTF-style `.maps` declarations.

## Raspberry Pi / IFB Experiment

```bash
BPF_MAP_API=legacy ./pi_deploy_cls_ifb.sh \
    phy0-ap0 eth0 root@192.168.3.2 ifb0 100mbit 100
```

Arguments are, in order:

```text
egress interface
ingress interface
SSH target
IFB interface
HTB bottleneck rate
per-band pfifo packet limit
```

The resulting queue hierarchy is:

```text
ifb0
└── HTB 10:
    └── class 10:1 (configured bottleneck rate)
        └── PRIO 1:
            ├── class 1:1 -> pfifo 101 (high priority)
            ├── class 1:2 -> pfifo 102
            └── class 1:3 -> pfifo 103 (best effort)
```

## Key Layout

`flow_id` is a directional IPv4 5-tuple:

```text
source IP, destination IP, source port, destination port, protocol
```

`pkt_id` embeds `flow_id` and adds one packet sequence. TCP uses its transport
sequence number. UDP uses a per-flow sequence generated at ingress and carried
to egress in `skb->mark`.

```text
flow_id: 16 bytes
pkt_id:  20 bytes
```

Changing either layout requires deleting stale pinned maps before loading the
new programs. The deployment scripts do this automatically.

## Verification

```bash
python3 -m unittest tests/test_key_layout.py

tc -s filter show dev eth0 ingress
tc -s filter show dev phy0-ap0 egress
tc -s -d qdisc show dev ifb0
tc -s -d class show dev ifb0
bpftool map show
```

Build artifacts, packet captures, generated logs and experiment outputs should
not be committed to the repository.
