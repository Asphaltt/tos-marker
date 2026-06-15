#!/bin/bash
# Create two netns (cli, srv) joined by a veth pair, IPv4-addressed.
# v4-mapped IPv6 connections emit real IPv4 packets, so this is all we need.
set -euo pipefail

# Idempotent: tear down a previous run (deleting the netns removes its veths).
ip netns del cli 2>/dev/null || true
ip netns del srv 2>/dev/null || true

ip netns add cli
ip netns add srv

# veth pair, one end in each netns
ip link add veth-cli netns cli type veth peer name veth-srv netns srv

ip -n cli addr add 10.0.0.1/24 dev veth-cli
ip -n srv addr add 10.0.0.2/24 dev veth-srv

for ns in cli srv; do
    ip -n "$ns" link set lo up
done
ip -n cli link set veth-cli up
ip -n srv link set veth-srv up

# Disable TCP ECN so the low 2 ToS bits stay 0 and the DSCP is unambiguous on the wire.
ip netns exec cli sysctl -wq net.ipv4.tcp_ecn=0
ip netns exec srv sysctl -wq net.ipv4.tcp_ecn=0
# v4-mapped must be permitted (0 = dual-stack allowed; this is the default).
ip netns exec cli sysctl -wq net.ipv6.bindv6only=0
ip netns exec srv sysctl -wq net.ipv6.bindv6only=0

echo "ready: cli(10.0.0.1) <-> srv(10.0.0.2)"
ip netns exec cli ping -c1 -W1 10.0.0.2 >/dev/null && echo "connectivity OK"
