#! /bin/sh

ip netns add host
ip netns add client

ip link add host_veth0 type veth peer name client_veth0

ip link set host_veth0 netns host
ip link set client_veth0 netns client

ip netns exec host ip addr add 192.168.0.1/24 dev host_veth0

ip netns exec host ip link set lo up
ip netns exec host ip link set host_veth0 up
ip netns exec client ip link set lo up
ip netns exec client ip link set client_veth0 up
