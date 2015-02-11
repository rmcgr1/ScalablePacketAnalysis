#!/usr/bin/python

import subprocess
import re

def split(file_name, size, nodes, max_size):
    file_size = 0
    packet_size_average = 0
    number_of_packets = 0

    cap_info = subprocess.Popen(["capinfos", file_name], stdout=subprocess.PIPE).communicate()[0]
    for i in cap_info.split("\n"):
        if i.startswith("Data size"):
            file_size = float(i.split()[2])
        if i.startswith("Average packet size"):
            packet_size_average = float(i.split()[3])
        if i.startswith("Number of packets"):
            number_of_packets = int(i.split()[3])

    # Compute number of packets to do the split on
    # Resulting size must be under max_size
    # Start with node number of chunks

    split_amount = number_of_packets / nodes
    subprocess.Popen(["editcap", "-c", str(split_amount), file_name, "chunk-" + file_name], stdout=subprocess.PIPE)

    '''
    100 / 5 nodes = 20 packets per node

    check packets per node * average packet size > max_size?
    handle empty/nonexistant files

    '''
      
split("test.pcap", 1000000, 3, 2000000)
