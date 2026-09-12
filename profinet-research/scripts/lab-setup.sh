#!/usr/bin/env bash
set -euo pipefail

# 1. Create network namespaces
sudo ip netns add ns-controller
sudo ip netns add ns-device

# 2. Create veth pair linking the two namespaces
sudo ip link add veth-controller type veth peer name veth-device

# 3. Move endpoints into their respective namespaces
sudo ip link set veth-controller netns ns-controller
sudo ip link set veth-device netns ns-device

# 4. Configure Controller interface & loopback
sudo ip netns exec ns-controller ip link set lo up
sudo ip netns exec ns-controller ip link set veth-controller address 02:00:00:00:00:01
sudo ip netns exec ns-controller ip addr add 192.168.1.10/24 dev veth-controller
sudo ip netns exec ns-controller ip link set veth-controller up

# 5. Configure Device interface & loopback
sudo ip netns exec ns-device ip link set lo up
sudo ip netns exec ns-device ip link set veth-device address 02:00:00:00:00:02
sudo ip netns exec ns-device ip addr add 192.168.1.20/24 dev veth-device
sudo ip netns exec ns-device ip link set veth-device up

echo "[+] PROFINET isolated L2 lab environment successfully provisioned."