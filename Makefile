BPF_CLANG ?= clang
BPF_MAP_API ?= legacy
ENABLE_IFB_REDIRECT ?= 0
IFACE ?= eth0

ifeq ($(BPF_MAP_API),legacy)
MAP_CFLAGS := -DBPF_MAP_LEGACY
else ifeq ($(BPF_MAP_API),libbpf)
MAP_CFLAGS :=
else
$(error BPF_MAP_API must be either "legacy" or "libbpf")
endif

CFLAGS := -O2 -g -target bpf -Wall -Wextra $(MAP_CFLAGS)
INGRESS_CFLAGS := $(CFLAGS) -DENABLE_IFB_REDIRECT=$(ENABLE_IFB_REDIRECT)

INGRESS_SRC := cls_dt_ingress.c
INGRESS_OBJ := cls_dt_ingress.o
EGRESS_SRC := cls_dt_egress.c
EGRESS_OBJ := cls_dt_egress.o

.PHONY: all clean load unload

all: $(INGRESS_OBJ) $(EGRESS_OBJ)

$(INGRESS_OBJ): $(INGRESS_SRC) cls_dt.h
	$(BPF_CLANG) $(INGRESS_CFLAGS) -c $< -o $@

$(EGRESS_OBJ): $(EGRESS_SRC) cls_dt.h
	$(BPF_CLANG) $(CFLAGS) -c $< -o $@

load: all
	sudo tc qdisc replace dev $(IFACE) clsact
	sudo tc filter replace dev $(IFACE) ingress bpf da obj $(INGRESS_OBJ) sec classifier
	sudo tc filter replace dev $(IFACE) egress bpf da obj $(EGRESS_OBJ) sec egress

unload:
	sudo tc qdisc del dev $(IFACE) clsact 2>/dev/null || true

clean:
	rm -f $(INGRESS_OBJ) $(EGRESS_OBJ)
