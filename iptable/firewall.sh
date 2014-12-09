#!/bin/bash

# Declare some variables
IPT=$(which iptables)

INT_ETH="eth0" 
EXT_ETH="eth1"

# Delete all existing rules
$IPT -F

# Set default chain policies
$IPT -P INPUT DROP
$IPT -P FORWARD DROP
$IPT -P OUTPUT DROP

# Allow loopback
$IPT -A INPUT -p icmp -j ACCEPT
$IPT -A OUTPUT -p icmp -j ACCEPT

# Allow icmp ping
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT

# Allow incoming SSH
$IPT -A INPUT -i $EXT_ETH -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $EXT_ETH -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

# Allow outgoing DNS
$IPT -A OUTPUT -o $EXT_ETH -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $EXT_ETH -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $EXT_ETH -p tcp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $EXT_ETH -p tcp --sport 53 -m state --state ESTABLISHED -j ACCEPT

# Allow incoming HTTP
$IPT -A INPUT -i $EXT_ETH -p tcp --dport 8080 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $EXT_ETH -p tcp --sport 8080 -m state --state ESTABLISHED -j ACCEPT
