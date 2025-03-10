#!/bin/bash
PART=3
# routing-info will not be used in part 3
python3 /shared/controller.py \
    --p4info /shared/l3_routing.p4info.txt \
    --bmv2-json /shared/l3_routing.json \
    --routing-info /shared/routing_info/r3_routing_info \
    --adj-info /shared/routing_info/r5_adj_info \
    --part $PART