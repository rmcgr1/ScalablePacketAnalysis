#!/bin/bash

# Useage: start|stop or run command...

if [ -z "$1" ]
then
    exit 0
fi

if [ "$1" == "start" ]
then
    VBoxManage startvm drone0_big #--type headless
    VBoxManage startvm drone1_big #--type headless
    VBoxManage startvm drone2_big #--type headless
    VBoxManage startvm drone3_big #--type headless
    VBoxManage startvm drone4_big #--type headless
    VBoxManage startvm drone5_big #--type headless
    VBoxManage startvm drone6_big #--type headless
    VBoxManage startvm drone7_big #--type headless
    exit 0
fi

if [ "$1" == "stop" ]
then
    for i in {0..7}
    do
	VBoxManage controlvm drone"$i"_big poweroff
	#VBoxManage guestcontrol drone"$i"_big execute "/sbin/shutdown" --username root --password $2  --wait-stdout -- "-h" "now"
    done
    exit 0
fi

#if [ -z "$2" ]
#then
#    for i in {0..3}
#    do
#	VBoxManage guestcontrol drone"$i"_big execute $1 --username user --password $3  --wait-stdout
#    done
#else
#    VBoxManage guestcontrol drone"$2"_big execute $1 --username user --password $3  --wait-stdout
#fi
