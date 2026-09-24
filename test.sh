#!/bin/bash
IP1="192.168.3.189"
IP2="192.168.3.127"

iperf3 -c "$IP1" -u -b 80M -l 1400 -t 30 &
PID1=$!
iperf3 -c "$IP2" -u -b 80M -l 1400 -t 30 &
PID2=$!

wait $PID1 $PID2
