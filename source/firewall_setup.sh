#!/bin/bash

# Firewall Configuration
sudo iptables -F
sudo sysctl net.ipv4.ip_forward=1
sudo iptables -P FORWARD ACCEPT
sudo iptables -F FORWARD
sudo iptables -t nat -F

# Accept already established connections
sudo iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# External machines -> Web server
sudo iptables -A FORWARD -i eth3 -p tcp --sport 1024: --dport 5000 -m state --state NEW --source 192.168.57.2 -d 192.168.55.2 -j ACCEPT

# Web server -> DB
sudo iptables -A FORWARD -i eth1 -p tcp --dport 5432 -m state --state NEW --source 192.168.55.2 -d 192.168.56.2 -j ACCEPT
# Create PostRouting rules
sudo iptables -t nat -A PREROUTING -d 192.168.55.2 -p tcp -j DNAT --to-destination 192.168.56.2
sudo iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE

# Redirect external connections to the web server
sudo iptables -t nat -A PREROUTING -i eth3 --dst 192.168.57.2 -p tcp --dport 5000 -j DNAT --to-destination 192.168.55.2