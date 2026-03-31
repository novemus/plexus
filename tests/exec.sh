#!/bin/bash

if [[ $# -lt 3 ]]; then
    echo "not enough arguments"
    exit 1
fi

loc_ip=`echo $1 | cut -d ":" -f 1`
loc_port=`echo $1 | cut -d ":" -f 2`
map_ip=`echo $2 | cut -d ":" -f 1`
map_port=`echo $2 | cut -d ":" -f 2`
rem_ip=`echo $3 | cut -d ":" -f 1`
rem_port=`echo $3 | cut -d ":" -f 2`
ifconfig=

lhs=${map_ip}${map_port}
rhs=${rem_ip}${rem_port}

if [ $lhs \> $rhs ]; then
    ifconfig="10.0.0.3 255.255.255.0"
else 
    ifconfig="10.0.0.2 255.255.255.0"
fi

openvpn --dev tap --ifconfig ${ifconfig} --local ${loc_ip} --lport ${loc_port} --remote ${rem_ip} --rport ${rem_port}
