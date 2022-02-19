#!/bin/bash

echo "$*"

if [[ $# -ne 6 ]]; then
    echo "not enough arguments"
    exit 1
fi

loc_ip=$1
loc_port=$2
map_ip=$3
map_port=$4
rem_ip=$5
rem_port=$6
ifconfig=

lhs=${map_ip}${map_port}
rhs=${rem_ip}${map_port}

if [ $lhs \> $rhs ]; then
    ifconfig="10.0.0.3 255.255.255.0"
else 
    ifconfig="10.0.0.2 255.255.255.0"
fi

openvpn --dev tap --ifconfig ${ifconfig} --local ${loc_ip} --lport ${loc_port} --remote ${rem_ip} --rport ${rem_port}
