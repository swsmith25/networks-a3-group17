#!/bin/bash

# Use the 'ip' command to list network interfaces and count them
interfaces=$(ip -o link show | awk -F': ' '{print $2}')
# Count the number of interfaces
num_interfaces=$(echo "$interfaces" | wc -l)
# exclude loop back
((num_interfaces--))

if [ $num_interfaces == '2' ]; then
simple_switch_grpc -i 1@eth0 -i 2@eth1 --no-p4  -- --grpc-server-addr 127.0.0.1:50051 --cpu-port 255 
elif [ $num_interfaces == '3' ]; then
simple_switch_grpc -i 1@eth0 -i 2@eth1 -i 3@eth2 --no-p4  -- --grpc-server-addr 127.0.0.1:50051 --cpu-port 255 
elif [ $num_interfaces == '4' ]; then
simple_switch_grpc -i 1@eth0 -i 2@eth1 -i 3@eth2 -i 4@eth3 --no-p4  -- --grpc-server-addr 127.0.0.1:50051 --cpu-port 255
else
echo "num_interfaces is not in the expected range"
fi
