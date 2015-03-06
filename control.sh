#!/bin/bash

if [ -z "$1" ]
then
    exit 0
fi

if [ "$1" == "start" ]
then
    VBoxManage startvm drone0 #--type headless
    VBoxManage startvm drone1 #--type headless
    VBoxManage startvm drone2 #--type headless
    VBoxManage startvm drone3 #--type headless
    exit 0
fi

if [ "$1" == "stop" ]
then
    for i in {0..3}
    do
	VBoxManage guestcontrol drone$i execute "/sbin/shutdown" --username root --password $3  --wait-stdout -- "-h" "now"
    done
    exit 0
fi

if [ -z "$2" ]
then
    for i in {0..3}
    do
	VBoxManage guestcontrol drone$i execute $1 --username user --password $3  --wait-stdout
    done
else
    VBoxManage guestcontrol drone$2 execute $1 --username user --password $3  --wait-stdout
fi
