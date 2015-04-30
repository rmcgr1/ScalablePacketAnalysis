#!/bin/bash
for i in {0..7}
do
    #ssh -t user@192.168.2.11"$i" "sudo nano /etc/network/interfaces"
    #ssh -t user@192.168.2.11"$i" "sudo echo 'dns-nameservers 8.8.8.8' >> /etc/network/interfaces"
    #ssh -t user@192.168.2.11"$i" "sudo reboot"
    ssh -t user@192.168.2.11"$i" "sudo apt-get update && sudo apt-get install tshark ngrep tcpdump -y"

    
    
    #VBoxManage guestcontrol drone"$i"_big execute "/sbin/reboot" --username root --password $3  --wait-stdout -- "-h" "now"
done
