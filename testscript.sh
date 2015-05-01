#!/bin/bash

DIR="/Users/irish/Development/ScalablePacketAnalysis"

cat > ./config.txt <<EOF
192.168.2.110
#192.168.2.111
#192.168.2.112
#192.168.2.113
#192.168.2.114
#192.168.2.115
#192.168.2.116
#192.168.2.117
EOF



$DIR/sshcontrol.py clean --verbose --user user --config ./config.txt
$DIR/sshcontrol.py distribute --verbose --user user --config ./config.txt $DIR/captures/maccdc2012_00016.pcap
$DIR/sshcontrol.py command --verbose --user user --config ./config.txt "tshark -T fields -e ip.src -e dns.qry.name -Y 'dns.flags.response eq 0'"
