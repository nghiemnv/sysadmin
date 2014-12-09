#!/bin/bash

# Declare some variables
IPT=$(which iptables)
SPAMLIST="blockedip"
SPAMDROPMSG="BLOCKED IP DROP"
NET="any/0"
DNS="8.8.8.8 8.8.4.4"
SERV_TCP="25 53 80 443"
SERV_UDP="53 123"
HI_PORTS="1024:65535"

INT_ETH="eth1" 
EXT_ETH=`/sbin/route | grep -i 'default' | awk '{print $8}'`

echo "Starting IPv4 Wall..."

# Delete all existing rules
$IPT -F
$IPT -X
$IPT -t nat -F
$IPT -t nat -X
$IPT -t mangle -F
$IPT -t mangle -X

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
