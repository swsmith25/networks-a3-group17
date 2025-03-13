#!/usr/bin/env python3
import argparse
import os
import sys
import ipaddress
from time import sleep, time, ctime
from datetime import timedelta


import grpc

# Import P4Runtime lib from parent utils dir
import utils.p4runtime_lib.bmv2 as bmv2
import utils.p4runtime_lib.helper as helper
from utils.p4runtime_lib.error_utils import printGrpcError
from utils.p4runtime_lib.switch import ShutdownAllSwitchConnections
from scapy.all import *
from multiprocessing import Process


ENABLED_PORT  = []
MAX_PORT = 4
CONTROLLER_OP_ARP_ENQUEUE = 0x00
CONTROLLER_OP_ARP_DEQUEUE = 0x01
CONTROLLER_OP_RIP = 0x02
CLONE_SESSION_ARP_REQ = 0x05
MAX_RIP_METRIC = 16
RIP_CMD_REQ = 0x01
RIP_CMD_RESPONSE = 0x02
RIP_BROADCAST_TIME = 10

# Routing table for Part 3
# Key: destination IP address
# Value : Route object includes the nextHopIP
#         and cost to the destination
routing_table = {}


# Routing information includes the nextHopIP and cost
class Route():
    def __init__(self, nextHopIP:str, cost:int):
        self.nextHopIP = nextHopIP
        self.cost = cost

    def mergeRoute(self, newRoute:Route) -> bool:
        # Part3_TODO: Complete the Route.mergeRoute method
        # This method compares the cost of self to that of newRoute.
        # If the newRoute's cost is smaller, update the self's attributes 
        # to those of newRoute and return True.
        # Otherwise, return False
        if (self.cost > newRoute.cost):
            self.nextHopIP = newRoute.nextHopIP
            self.cost = newRoute.cost
            return True
        return False
        
def dump_routing_table():
    for destIP, route in routing_table.items():
        print (f"Route to {destIP}: via {route.nextHopIP}, cost is {route.cost}")
        
def construct_router_info():
    port_to_ip_mac = {}
    for port in range(MAX_PORT):
        ip_addr_result = os.popen(f'ip addr show eth{port}').read().split("inet ")
        if (ip_addr_result[0] == ''):
            break
        ip = ip_addr_result[1].split("/")[0]
        mac = os.popen(f'ip link show eth{port}').read().split("link/ether ")[1].split(" ")[0]
        print(ip,mac)
        port_to_ip_mac[port+1] = (ip,mac)
        ENABLED_PORT.append(port+1)
    print("Enabled port on the router:", ENABLED_PORT)
    return port_to_ip_mac

# 1. Initalize necessary tables for ICMP and ARP packet handling.
# 2. Initialize a static routing table for the adjacent network devices.
# 3. Broadcast RIP request to the adjacent network devices.
def init_part3(p4info_helper, s1, port_to_ip_mac:dict, adj_info:str):
    replicas = [{'egress_port':port, 'instance': port} for port in ENABLED_PORT]
    clone_session_entry = p4info_helper.buildCloneSessionEntry(
        clone_session_id=CLONE_SESSION_ARP_REQ,
        replicas=replicas
    )
    s1.WritePREEntry(clone_session_entry)
    
    for port, pair in port_to_ip_mac.items():
        ip, mac = pair
        print ("Add router port to ip mapping", port, ip)
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.icmp_ingress_port_ip",
            match_fields={"standard_metadata.ingress_port": port},
            action_name="MyIngress.change_src_ip",
            action_params={"port_ip": ip}
        )
        s1.WriteTableEntry(table_entry)
        
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.is_router_ip",
            match_fields={"hdr.ipv4.dstAddr": ip},
            action_name="NoAction"
        )
        s1.WriteTableEntry(table_entry) 
        
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.arp_check_target",
            match_fields={"hdr.arp.tgtIP": ip},
            action_name="MyIngress.send_ARP_response",
            action_params={"sndMAC": mac}
        )
        s1.WriteTableEntry(table_entry)
        
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyEgress.port_to_ARP_request",
            match_fields={"standard_metadata.egress_port": port},
            action_name="MyEgress.send_ARP_request",
            action_params={"port_ip": ip,
                        "port_mac": mac}
        )
        s1.WriteTableEntry(table_entry)
    
    # Add routing table entries for neighborhoods
    with open(adj_info, 'r') as f:
        for line in f:
            neighbor_routes = line.split(',')
            neighborIP = neighbor_routes[0]
            cost = int(neighbor_routes[1])
            routing_table[neighborIP] = Route(
                nextHopIP=neighborIP,
                cost=cost
            ) 
            print ("Add routing table entry for neighborhoods", neighborIP)
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv4_route",
                match_fields={"hdr.ipv4.dstAddr": (neighborIP, 32)},
                action_name="MyIngress.forward_to_next_hop",
                action_params={"next_hop": neighborIP}
            )
            s1.WriteTableEntry(table_entry)
        
    # multicast RIP request
    for port, pair in port_to_ip_mac.items():
        ip, mac = pair
        ripRequest = Ether(src=mac,dst="ff:ff:ff:ff:ff:ff")/ \
            IP(src=ip,dst="224.0.0.9")/ \
            UDP(sport=520, dport=520)/ \
            RIP(cmd=RIP_CMD_REQ,version=2)/ \
            RIPEntry(AF=0,metric=MAX_RIP_METRIC)
        
        s1.sendPktToSwitch(payload=bytes(ripRequest), metadata=[port])

    # Set a timer for RIP unsolicited broadcast 
    # Use dummy table entry as a timer
    table_entry = p4info_helper.buildTableEntry(
                table_name="MyEgress.dummy",
                match_fields={"standard_metadata.ingress_port": 129},
                action_name="NoAction",
            )
    table_entry.idle_timeout_ns = int (RIP_BROADCAST_TIME * 1e9)
    s1.WriteTableEntry(table_entry) 

# 1. Initalize necessary tables for ICMP and ARP packet handling.
# 2. Initialize static routing table.         
def init_part2(p4info_helper, s1, port_to_ip_mac:dict, routing_info:str):
    replicas = [{'egress_port':port, 'instance': port} for port in ENABLED_PORT]
    clone_session_entry = p4info_helper.buildCloneSessionEntry(
        clone_session_id=CLONE_SESSION_ARP_REQ,
        replicas=replicas
    )
    s1.WritePREEntry(clone_session_entry)
    
    for port, pair in port_to_ip_mac.items():
        ip, mac = pair
        print ("Add router port to ip mapping", port, ip)
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.icmp_ingress_port_ip",
            match_fields={"standard_metadata.ingress_port": port},
            action_name="MyIngress.change_src_ip",
            action_params={"port_ip": ip}
        )
        s1.WriteTableEntry(table_entry)
        
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.is_router_ip",
            match_fields={"hdr.ipv4.dstAddr": ip},
            action_name="NoAction"
        )
        s1.WriteTableEntry(table_entry) 
        
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.arp_check_target",
            match_fields={"hdr.arp.tgtIP": ip},
            action_name="MyIngress.send_ARP_response",
            action_params={"sndMAC": mac}
        )
        s1.WriteTableEntry(table_entry)
        
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyEgress.port_to_ARP_request",
            match_fields={"standard_metadata.egress_port": port},
            action_name="MyEgress.send_ARP_request",
            action_params={"port_ip": ip,
                        "port_mac": mac}
        )
        s1.WriteTableEntry(table_entry)
    
    # Add static routing table
    with open(routing_info, 'r') as f:
        for line in f:
            ip_mac_pair = line.split(',')
            prefix, prefix_len = ip_mac_pair[0].split('/')
            next_hop_ip = ip_mac_pair[1]
            next_hop_mac = ip_mac_pair[2]
            egress_mac = ip_mac_pair[3]
            egress_port = int(ip_mac_pair[4].strip('\n'))

            print ("Add routing table entry", prefix, prefix_len, next_hop_ip)
            prefix_len = int(prefix_len)

            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv4_route",
                match_fields={"hdr.ipv4.dstAddr": (prefix,prefix_len)},
                action_name="MyIngress.forward_to_next_hop",
                action_params={"next_hop": next_hop_ip}
            )
            s1.WriteTableEntry(table_entry)
                   

# 1. Initalize necessary tables for ICMP message handling.
# 2. Initialize static routing table and ARP table. 
def init_part1(p4info_helper, s1, port_to_ip_mac:dict, routing_info:str):
    
    # Initialize necessary tables for ICMP message handling
    for port, pair in port_to_ip_mac.items():
        ip, mac = pair
        print ("Add router port to ip mapping", port, ip)
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.icmp_ingress_port_ip",
            match_fields={"standard_metadata.ingress_port": port},
            action_name="MyIngress.change_src_ip",
            action_params={"port_ip": ip}
        )
        s1.WriteTableEntry(table_entry)
        
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.is_router_ip",
            match_fields={"hdr.ipv4.dstAddr": ip},
            action_name="NoAction"
        )
        s1.WriteTableEntry(table_entry) 
    
    # Add static routing table and Arp table
    with open(routing_info, 'r') as f:
        for line in f:
            ip_mac_pair = line.split(',')
            prefix, prefix_len = ip_mac_pair[0].split('/')
            next_hop_ip = ip_mac_pair[1]
            next_hop_mac = ip_mac_pair[2]
            egress_mac = ip_mac_pair[3]
            egress_port = int(ip_mac_pair[4].strip('\n'))

            print ("Add routing table entry", prefix, prefix_len, next_hop_ip)
            prefix_len = int(prefix_len)

            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv4_route",
                match_fields={"hdr.ipv4.dstAddr": (prefix,prefix_len)},
                action_name="MyIngress.forward_to_next_hop",
                action_params={"next_hop": next_hop_ip}
            )

            print ("Add ARP table entry", next_hop_ip,next_hop_mac,egress_mac)
            s1.WriteTableEntry(table_entry)
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.arp_table",
                match_fields={"meta.next_hop": next_hop_ip},
                action_name="MyIngress.change_dst_mac",
                action_params={"dst_mac": next_hop_mac}
            )

            print ("Add MAC table entry", next_hop_mac,egress_port)

            s1.WriteTableEntry(table_entry)
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.dmac_forward",
                match_fields={"hdr.ethernet.dstAddr": next_hop_mac},
                action_name="MyIngress.forward_to_port",
                action_params={"egress_port": egress_port,
                                "egress_mac": egress_mac}
            )
            s1.WriteTableEntry(table_entry)      
    

def main(p4info_file_path, bmv2_file_path, routing_info, adj_info, part):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        s1 = bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
        )

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                   bmv2_json_file_path=bmv2_file_path)
        print ("Installed P4 Program using SetForwardingPipelineConfig on %s" % s1.name)
        
        port_to_ip_mac = construct_router_info() 

        if (part == 3):
            print ("Initialization for Part 3")
            init_part3(p4info_helper, s1, port_to_ip_mac, adj_info)
        elif (part == 2):
            print ("Initialization for Part 2")
            init_part2(p4info_helper, s1, port_to_ip_mac, routing_info)
        elif (part == 1):
            print ("Initialization for Part 1")
            init_part1(p4info_helper, s1, port_to_ip_mac, routing_info)
            sleep(5)
            print ("Static table insertion done, exit...")
            ShutdownAllSwitchConnections()
            return 
        else:
            print ("Commend line argument --part should be between 1 and 3")
            raise ValueError
       
        # Packet buffer for the packet waiting for an ARP reply 
        # key: next_hop IP addr in int
        # value: a tuple consists of req sent time, req count, and a packet list.
        pkt_buffer = dict()
        
        while (True):
            msg = s1.ReadfromSwitch()
            if (msg.HasField('packet')):
                op = int.from_bytes(msg.packet.metadata[0].value) 
                if (op == CONTROLLER_OP_ARP_ENQUEUE):
                    # Handle ARP miss
                    print ("Broadcast ARP requests to neighbors")
                    next_hop = int.from_bytes(msg.packet.metadata[1].value)
                    print ("next_hop_ip", str(ipaddress.ip_address(next_hop)))
                    print ("next_hop_ip in int:", next_hop)
                    
                    if (next_hop not in pkt_buffer):
                        # initialize pkt_buffer_entry
                        pkt_buffer[next_hop] = [0.0, 0, []]
                    elif (pkt_buffer[next_hop] == None):
                        # race condition, ARP rule is already installed
                        # but a switch issues arp_enqueue before the installation
                        print ("Send packet to switch")
                        s1.sendPktToSwitch(payload=msg.packet.payload)
                        continue
                    # ARP is not done yet, enqueue the packet.
                    print ("Enqueue packet")
                    pkt_buffer[next_hop][0] = time.time()
                    pkt_buffer[next_hop][1] += 1
                    pkt_list = pkt_buffer[next_hop][2]
                    pkt_list.append(msg.packet.payload)

                elif (op == CONTROLLER_OP_ARP_DEQUEUE): 
                    # Handle ARP reply
                   
                    # Retrieve ARP information from the source fields in the ARP header

                    # Router port number that the response came in
                    egress_port = int.from_bytes(msg.packet.metadata[1].value)
                    pkt = Ether(msg.packet.payload)
                    next_hop_ip = pkt[ARP].psrc # This is src protocol (IP) address
                    next_hop_mac = pkt[ARP].hwsrc # This is src hw (MAC) address
                    egress_mac = pkt[Ether].dst # The MAC address of the ingress port

                    print ("Receives ARP reply")
                    print ("egress port in int:", egress_port)
                    
                    # DONE
                    ### PART2_TODO: Add arp_table and dmac_forward table entries
                    ### using the above information from ARP reply
                    ### Use p4info_helper.buildTableEntry and s1.WriteTableEntry as in A2
                    print("Add ARP table entry", next_hop_ip, next_hop_mac)
                    arp_table_entry = p4info_helper.buildTableEntry(
                        table_name="MyIngress.arp_table",
                        match_fields={"meta.next_hop": next_hop_ip},
                        action_name="MyIngress.change_dst_mac",
                        action_params={"dst_mac": next_hop_mac},
                    )
                    s1.WriteTableEntry(arp_table_entry)

                    print("Add MAC table entry", next_hop_mac, egress_port, egress_mac)
                    dmac_forward_entry = p4info_helper.buildTableEntry(
                        table_name="MyIngress.dmac_forward",
                        match_fields={"hdr.ethernet.dstAddr": next_hop_mac},
                        action_name="MyIngress.forward_to_port",
                        action_params={
                            "egress_port": egress_port,
                            "egress_mac": egress_mac,
                        },
                    )
                    s1.WriteTableEntry(dmac_forward_entry)
                        
                    # Dequeue packets waiting for the ARP reply
                    next_hop_int = int(ipaddress.ip_address(next_hop_ip))
                    print ("next hop ip in str ", str(ipaddress.ip_address(next_hop_ip)))
                    print ("next hop ip in int: ", next_hop_int)
                    # check if any packet to next_hop has been enqueued
                    if (next_hop_int in pkt_buffer and pkt_buffer[next_hop_int] is not None):
                        for pkt in pkt_buffer[next_hop_int][2]:
                            s1.sendPktToSwitch(payload=pkt)
                        pkt_buffer[next_hop_int] = None # marked as resolved
                    else:
                        print ("Do nothing. All packets related to the next_hop are already dequeued.")
                    
                elif (op == CONTROLLER_OP_RIP):
                    pkt = Ether(msg.packet.payload)
                    egress_port = int.from_bytes(msg.packet.metadata[1].value)
                    ip, mac = port_to_ip_mac[egress_port]
                    
                    if (pkt[RIP].cmd == RIP_CMD_REQ):
                        # Handle RIP request
                        print ("Receives RIP reqeust from ", pkt[IP].src)
                        # Only handles the RIP request queries all route entries.
                        # Those requests are broadcasted when a router is initialized.
                        if (pkt[RIPEntry].AF == 0 and pkt[RIPEntry].metric==MAX_RIP_METRIC):
                            print ("Send all routing table information")
                            ripResponse = Ether(src=mac,dst=pkt[Ether].src)/ \
                                IP(src=ip,dst=pkt[IP].src)/ \
                                UDP(sport=520, dport=520)/ \
                                RIP(cmd=RIP_CMD_RESPONSE,version=2)
                                
                            for destIP, route in routing_table.items():
                                ripResponse = ripResponse/ \
                                    RIPEntry(addr=destIP,
                                        mask='255.255.255.255',
                                        nextHop='0.0.0.0',
                                        metric=route.cost
                                    )
                            s1.sendPktToSwitch(payload=bytes(ripResponse), metadata=[egress_port])
                    elif (pkt[RIP].cmd == RIP_CMD_RESPONSE):
                        # Handle RIP response
                        print ("Receives RIP response from ", pkt[IP].src)
                        numEntry = len(pkt[RIPEntry])//20
                        for i in range(numEntry):
                            entry = pkt[RIPEntry][i]
                            # Retrieve routing information from RIP response
                            newRoute = Route(
                                nextHopIP=pkt[IP].src,
                                cost=entry.metric+1
                                # increment cost by 1 since there is an additional hop 
                                # between the sender and the router
                            )
                            if (entry.addr in routing_table):
                                # The address in the RIP response is in the routing table
                                
                                # PART3_TODO: Try to merge routes and update the routing table on success.
                                # 1. Merge an existing route (routing_Table[entry.addr]) with 
                                #    newRoute using the mergeRoute method. 
                                merge = routing_table[entry.addr].mergeRoute(newRoute)
                                # 2. If the method returns True, update the ipv4_route table in the data plane.
                                # * Use prefix_length of 32 for the match_fields parameter of buildTableEntry
                                # * Specify is_modify=True as the parameter of WriteTableEntry
                                if (merge):
                                    print ("Updating routing table entry for RIP response", entry.addr)  # TODO entry.addr or newRoute.nextHopIP???
                                    table_entry = p4info_helper.buildTableEntry(
                                        table_name="MyIngress.ipv4_route",
                                        match_fields={"hdr.ipv4.dstAddr": (entry.addr, 32)},
                                        action_name="MyIngress.forward_to_next_hop",
                                        action_params={"next_hop": newRoute.nextHopIP}
                                    )
                                    s1.WriteTableEntry(table_entry, is_modify=True)
                                # 3. If the method returns False, do nothing since there's no update.
                                pass
                            else:
                                # PART3_TODO: Route to a new address, add it.
                                # 1. Add it to the routing_table dictionary using 
                                # entry.addr as a key and new Route as a value.
                                routing_table[entry.addr] = newRoute
                                # 2. Insert a table entry to the ipv4_route table in the data plane. 
                                # * Use prefix_length of 32 for the match_fields parameter of buildTableEntry
                                print ("Add routing table entry for RIP response", entry.addr)  # TODO entry.addr or newRoute.nextHopIP???
                                table_entry = p4info_helper.buildTableEntry(
                                    table_name="MyIngress.ipv4_route",
                                    match_fields={"hdr.ipv4.dstAddr": (entry.addr, 32)},
                                    action_name="MyIngress.forward_to_next_hop",
                                    action_params={"next_hop": newRoute.nextHopIP}
                                )
                                s1.WriteTableEntry(table_entry)
                                pass
                                
                        dump_routing_table()

            # Use dummy table's timeout as a timer for RIP unsolicited response
            if (msg.HasField('idle_timeout_notification')):
                table_entries = msg.idle_timeout_notification.table_entry
                for table_entry in table_entries:
                    s1.DeleteTableEntry(table_entry)
                
                # send RIP response every RIP_BROADCAST_TIME seconds
                print("Broadcast unsolicited RIP response")
                for port, pair in port_to_ip_mac.items():
                    ip, mac = pair
                    # unsolicited RIP response
                    ripResponse = Ether(src=mac,dst="ff:ff:ff:ff:ff:ff")/ \
                        IP(src=ip,dst="224.0.0.9")/ \
                        UDP(sport=520, dport=520)/ \
                        RIP(cmd=RIP_CMD_RESPONSE,version=2)
                        
                    for destIP, route in routing_table.items():
                        ripResponse = ripResponse/ \
                            RIPEntry(addr=destIP,
                                mask='255.255.255.255',
                                nextHop='0.0.0.0',
                                metric=route.cost
                            )
                    s1.sendPktToSwitch(payload=bytes(ripResponse), metadata=[port])
                
                # Reset the timer
                dummy_table_entry = p4info_helper.buildTableEntry(
                    table_name="MyEgress.dummy",
                    match_fields={"standard_metadata.ingress_port": 129},
                    action_name="NoAction",
                )
                dummy_table_entry.idle_timeout_ns = int (RIP_BROADCAST_TIME * 1e9)
                s1.WriteTableEntry(dummy_table_entry) 
                
    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)
    
    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=True)
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=True)
    parser.add_argument('--routing-info', help='Routing info file',
                        type=str, action="store", required=True)
    parser.add_argument('--adj-info', help='Adjacecy info file',
                        type=str, action="store", required=True)
    parser.add_argument('--part', help='Please specify the Part you are trying to test in a number',
                        type=int, action="store", required=True)
    
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    if not os.path.exists(args.routing_info):
        parser.print_help()
        print("\nrouting_info file not found." % args.bmv2_json)
        parser.exit(1)
    
    main(args.p4info, args.bmv2_json, args.routing_info, args.adj_info, args.part)
