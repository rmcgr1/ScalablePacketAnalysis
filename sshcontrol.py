#!/usr/bin/python

usage = """shakedown.

Usage:
   shakedown distribute --user <username> --host <host>... <files>...
   shakedown command --user <username> --host <host>... <command>
   shakedown clean --user <username> --host <host>...

Options:

--host <host>         Hostname or IP address.
--user <username>     Username to ssh 

Example:

Note! It is requrired to set up password-less ssh with the different nodes!

distribute capture files to drones:
shakedown distribute --user user --host 192.168.1.100 --host 192.168.1.101 capture1.pcap capture2.pcap

run commands:
shakedown command --user user --host 192.168.1.100 --host 192.168.1.101 "tshark fields -e ip.src -e dns.qry.name -Y 'dns.flags.response eq 0'"

remove transfered files from nodes:
shakedown clean --user user --host 192.168.1.100 --host 192.168.1.101 


Config file?
Using Master?
Specify working dirs?


"""







import paramiko
import sys
import os
import subprocess
import time
import re
import Queue
import threading
from itertools import cycle
from docopt import docopt




# TODO cover for trailing slash
#CAPTURE_DIR = "./captures/"
DRONE_DIR = "/tmp/packet_analysis/"
#HOST_LIST = ['192.168.2.100', '192.168.2.101', '192.168.2.102', '192.168.2.103']

class Drone:
    def __init__(self, ipaddress):
        self.ipaddress = ipaddress
        self.freespace = None
        self.sshconn = None
        self.filelist = []
'''
TODO:

use master too
modify command to strip out -r, -w, -I
recieve result
error handling
survey nodes for existing files with hash
'''

def setup(d):
    # See if the right programs are installed
    needed_programs = ['tshark', 'editcap', 'ngrep', 'rsync']
    
    for i in needed_programs:
        stdin, stdout, stderr = d.sshconn.exec_command("which " + i)
        if i not in stdout.read():
            print "[!] Error " + i + " not installed on " + str(d)

    # Make working directory
    stdin, stdout, stderr = d.sshconn.exec_command("mkdir -p " + DRONE_DIR)

    # Get Available Space
    stdin, stdout, stderr = d.sshconn.exec_command("df -B1 /tmp | tail -n +2 | awk '{print$4}'")
    d.freespace = int(stdout.read())


def getSSHConn(d, ssh_user):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(d.ipaddress, username=ssh_user)
    except paramiko.AuthenticationException:
        print "Authentication failed when connecting to " + str(d.ipaddress)
        raise
    except:
        print "Could not SSH to waiting for it to start" + str(d.ipaddress)
        raise
    return ssh

def create_split(drone_list, file_list):
    for file in file_list:
        if file.endswith(".pcap"):
            print file
            #file_list.append(os.path.abspath(CAPTURE_DIR) + "/" + file)
            file_list.append(file)

    # Compute split size
    total_file_size = 0
    for i in file_list:
        total_file_size = total_file_size + os.path.getsize(i)

    # See if the size is OK with taking up no more than 85% of available free space on the least free drone
    least_free_space = sys.maxint
    for d in drone_list:
        if least_free_space > d.freespace:
            least_free_space = d.freespace
            
    least_free_space = least_free_space * .85
    number_of_drones = len(drone_list)

    print str(least_free_space)
    print str(total_file_size / number_of_drones)
    max_chunk_file_size = total_file_size / number_of_drones
    
    if (total_file_size / number_of_drones) < least_free_space:
        # Good to go
        print "Good to seperate files upto this size: " + str(total_file_size / number_of_drones)

        # Have to get the size of each chunk, especially if ealing with multiple various sized files
        # Punting on problem by splitting each file into 1/numofdrones
        '''
        A - 50 mb
        B - 10 mb
        C - 100 mb
        
        total 160mb / 2 nodes = 80mb per node, 
        '''
        # TODO this math is way off
        split_size = str((total_file_size / number_of_drones) / 6)
        split(file_list, number_of_drones, split_size, max_chunk_file_size) 
    
    else:
        print "[!] Error: not enough free space on drones"
        print "TODO handle this"

def split(file_list, nodes, split_size, max_size):
    for f in file_list:
        file_size = 0
        packet_size_average = 0
        number_of_packets = 0

        subprocess.check_call(["tcpdump", "-r", f, "-w", f + "-chunk", "-C", split_size], stdout=subprocess.PIPE)

def transfer_split_files(drone_list):
    # Transfer the list of "chunked" files to drones and master
    worker_pool = cycle(drone_list)

    distributed_files = read_existing_files(drone_list)
    
    # TODO Check free space??
    for file in os.listdir(CAPTURE_DIR):

        if "chunk" in file:

            if [file, str(os.path.getsize(CAPTURE_DIR + file))] in distributed_files:
                # This file is already out on a drone
                continue
                           
            d = worker_pool.next()
            # if d.ipaddress == "127.0.0.1":
            # reserve file for Master
            # d.filelist.append(file)
            #else:
            subprocess.check_call(["rsync", "-avz", "-e", "ssh", CAPTURE_DIR + file, SSH_USER + "@" + d.ipaddress + ":" + DRONE_DIR], stdout=subprocess.PIPE)
            d.filelist.append(file)

    # TODO get master in drone list
    #for d in drone_list:
    #    print d.ipaddress + " " + str(d.filelist)


def send_command(drone, cmd, q):
    stdin, stdout, stderr = drone.sshconn.exec_command(cmd)
    result = stdout.read()
    q.put(result)

        
def distribute_command(drone_list, cmd):
    q = Queue.Queue()
    thread_list = []
    for d in drone_list:
        t = threading.Thread(target=send_command, args = (d,cmd,q))
        t.daemon = True
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join()
        
    result = []
    print "here"
    
    while not q.empty():
        try:
            result.append(q.get())
        except:
            pass

    for i in result:
        print i

# Remove files to be transfered if they exist out on a drone
def read_existing_files(drone_list):
    #check name and size and remove from file list to distribute
    existing_file_list = []
    
    for d in drone_list:
        stdin, stdout, stderr = d.sshconn.exec_command("ls -l " + DRONE_DIR + " | grep 'chunk' | awk '{print $9, $5}'")
        result = stdout.read()
        existing_file_list.append([result.split()[0], result.split()[1]])

    return existing_file_list



def clean_drones(drone_list):
    for d in drone_list:
        stdin, stdout, stderr = d.sshconn.exec_command("rm `ls " + DRONE_DIR + " | grep 'chunk'`")

def main():

    # interface of distribute, command, clear
   
    drone_list = []


    arguments = docopt(usage)
    print arguments


    ssh_user = arguments['--user']
    host_list = arguments['--host']
        
    for ip in host_list:
        # Create Drone
        drone_list.append(Drone(ip))
        
    for d in drone_list:
        d.sshconn = getSSHConn(d, ssh_user)        
        setup(d)


    # Either clean, distribute or command

    if arguments['distribute']:

        file_list = arguments['<files>']
        # Prepare captures
        create_split(drone_list, file_list)
        transfer_split_files(drone_list, file_list)

        print "[*] Finished transfering files to drones"


    if arguments['command']:
        #cmd = "tshark -r /tmp/packet_analysis/*pcap* -T fields -e ip.src -e dns.qry.name -Y 'dns.flags.response eq 0'"
        cmd = sanitize_command(arguments['<command>'])
        distribute_command(drone_list, cmd)
    
    if arguments['clean']:
        clean_drones(drone_list)
        
        
    # Shut it down
    for d in drone_list:
        d.sshconn.close()


if __name__ == "__main__":
    main()
        
    
