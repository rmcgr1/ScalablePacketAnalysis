#!/usr/bin/python

usage = """shakedown.

Usage:
   shakedown distribute [options] --user <username> (--host <host>... | --config <configfile>) <pcapfiles>...
   shakedown command [options] --user <username> (--host <host>... | --config <configfile>)  <command>
   shakedown clean [options] --user <username> (--host <host>... | --config <configfile>)

Options:
--name <name>         Execute commands only on files that have been distributed that contain <name>, the default is to process all distributed files 
--verbose
--host <host>         Hostname or IP address.
--user <username>     Username to ssh 
--balance             Enable load balancing.  Shifts data from poorly performing to nodes to high performing ones
--balancethreshold <threshold>    Percent difference between nodes to attempt to correct (default .10).  Lower value, higher performance, more transfers

Example:

Note! It is requrired to set up password-less ssh with the different nodes!

distribute capture files to drones:
shakedown distribute --user user --host 192.168.1.100 --host 192.168.1.101 capture1.pcap capture2.pcap

run commands:
shakedown command --user user --host 192.168.1.100 --host 192.168.1.101 "tshark -T fields -e ip.src -e dns.qry.name -Y 'dns.flags.response eq 0'"
(don't use -r (readfile) commands for tcpdump,tshark or -I for ngrep, the program will handle this)


remove transfered files from nodes:
shakedown clean --user user --host 192.168.1.100 --host 192.168.1.101 


Config file?
make user an optional option and handle if its not there
make transfer threaded
clean chunks after transfer

./sshcontrol.py distribute --verbose --user user --host 192.168.2.100 --host 192.168.2.101 --host 192.168.2.102 --host 192.168.2.103 ./captures/maccdc2012_00016.pcap
./sshcontrol.py command  --verbose --user user --host 192.168.2.100 --host 192.168.2.101 --host 192.168.2.102 --host 192.168.2.103 "tshark -T fields -e ip.src -e dns.qry.name -Y 'dns.flags.response eq 0'"

"""


import paramiko
import sys
import os
import subprocess
import time
import re
import Queue
import threading
import operator
import math
from random import shuffle
from itertools import cycle
from docopt import docopt
import pdb
import timeit


# TODO cover for trailing slash
#CAPTURE_DIR = "./captures/"
DRONE_DIR = "/tmp/packet_analysis/"
#HOST_LIST = ['192.168.2.100', '192.168.2.101', '192.168.2.102', '192.168.2.103']
VERBOSE = False
OUTPUT = True

class Drone:
    def __init__(self, ipaddress):
        self.ipaddress = ipaddress
        self.freespace = None
        self.sshconn = None
        self.filelist = []
        self.ssh_user = None
        self.freemem = None
        self.completiontime = 0

    def time_per_file(self):
        if len(self.filelist) == 0:
            return 0
        return self.completiontime / len(self.filelist)
        
'''
TODO:

out of mem issue
error handling
config file?
use master too
progress of individual nodes
recieve result
error handling - especially distributing the command to dronesb
survey nodes for existing files with hash
large files chop to 50 mb and run with that
'''

def setup_drone(d, ssh_user):
    d.ssh_user = ssh_user
    try:
        d.sshconn = paramiko.SSHClient()
        d.sshconn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        d.sshconn.connect(d.ipaddress, username=d.ssh_user)
    except paramiko.AuthenticationException:
        print "Authentication failed when connecting to " + str(d.ipaddress)
        raise
    except:
        print "Could not SSH to " + str(d.ipaddress)
        raise

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

    # Get Available Memory
    stdin, stdout, stderr = d.sshconn.exec_command("free -m | grep 'Mem:' | awk '{print$2}'")
    d.freemem = int(stdout.read())

####
# Distributing Files
####

def create_split(drone_list, file_list):
    chunked_file_list = []
    
    # Compute split size
    total_file_size = 0
    for i in file_list:
        total_file_size = total_file_size + os.path.getsize(i)

    # See if the size is OK with taking up no more than 85% of available free space on the least free drone
    least_free_space = sys.maxint
    for d in drone_list:
        if least_free_space > d.freespace:
            least_free_space = d.freespace

    # Lets start with no file larger than 
            
    least_free_space = least_free_space * .85
    number_of_drones = len(drone_list)

    if VERBOSE:
        print "[*] Least amount of free disk space on drones (bytes): " + str(least_free_space)
        print "[*] Make chunks of size (bytes): " + str(total_file_size / number_of_drones)

    max_chunk_file_size = total_file_size / number_of_drones


    
    if (total_file_size / number_of_drones) < least_free_space:
        # Good to go
        if VERBOSE:
            print "Good to seperate files upto this size: " + str(total_file_size / number_of_drones)
            

        # Have to get the size of each chunk, especially if ealing with multiple various sized files
        # Punting on problem by splitting each file into 1/numofdrones
        # TODO this math is way off
        split_size = str((total_file_size / number_of_drones) / 6)

        split_size  = 25

        split(file_list, number_of_drones, split_size, max_chunk_file_size) 
    
    else:
        print "[!] Error: not enough free space on drones"
        print "TODO handle this"
        sys.exit(1)

    # Get list of chunked files
    for i in file_list:
        for fname in os.listdir(os.path.dirname(i)):
            if "chunk" in fname:
                chunked_file_list.append(os.path.join(os.path.dirname(i),fname))

    return chunked_file_list
        
def split(file_list, nodes, split_size, max_size):
    for f in file_list:
        file_size = 0
        packet_size_average = 0
        number_of_packets = 0
        try:
            subprocess.check_call(["tcpdump", "-r", f, "-w", f + "-chunk", "-C", str(split_size)], stdout=subprocess.PIPE)
        except:
            print "[!] Error: tcpdump couldn't split " + f
            sys.exit(1)


def transfer_thread(d, fname):
    if VERBOSE:
        print "[*] transfering " + fname + " to " + d.ipaddress
    subprocess.check_call(["rsync", "-avz", "-e", "ssh", fname, d.ssh_user + "@" + d.ipaddress + ":" + DRONE_DIR], stdout=subprocess.PIPE)
    d.filelist.append(fname)

            
def transfer_split_files(drone_list, chunked_file_list):
    
    # Transfer the list of "chunked" files to drones
    worker_pool = cycle(drone_list)

    distributed_files = read_existing_files(drone_list)
    if VERBOSE:
        print "[*] Already distributed files: " + str(distributed_files)

    thread_list = []
    for fname in chunked_file_list:

        if [fname.split('/')[-1], str(os.path.getsize(fname))] in distributed_files:
            # This file is already out on a drone
            continue

                           
        d = worker_pool.next()

        if VERBOSE:
            print "[*] transfering " + fname + " to " + d.ipaddress
        subprocess.check_call(["rsync", "-avz", "-e", "ssh", fname, d.ssh_user + "@" + d.ipaddress + ":" + DRONE_DIR], stdout=subprocess.PIPE)
        d.filelist.append(fname)

'''
        time.sleep(1)
        
        t = threading.Thread(target=transfer_thread, args = (d,fname))
        t.daemon = True
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join()
'''
    
# Remove files to be transfered if they exist out on a drone
def read_existing_files(drone_list):
    #check name and size and remove from file list to distribute
    existing_file_list = []
    
    for d in drone_list:
        d.filelist = []
        stdin, stdout, stderr = d.sshconn.exec_command("ls -l " + DRONE_DIR + " | grep 'chunk' | awk '{print $9, $5}'")
        result = stdout.read()
        if result == '':
            continue
        for i in result.split('\n'):
            if i is not '':
                existing_file_list.append([i.split()[0], i.split()[1]])
                d.filelist.append(i.split()[0])
                
    return existing_file_list


####
# Command Distribution 
####
    
def send_command(d, cmd, q):
    stdin, stdout, stderr = d.sshconn.exec_command(cmd)
    start_time = timeit.default_timer()
    if VERBOSE:
        print "[*] sent command " + str(d.ipaddress)
    result = stdout.read()

    d.completiontime = timeit.default_timer() - start_time
    #print "" + str(d.ipaddress) + ": " + str(d.completiontime)
    if OUTPUT:
        print str(d.completiontime)+", ",
    q.put(result)

        
def distribute_command(drone_list, cmd):

    if OUTPUT:
        print str(len(drone_list))+",", 
    
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
    
    while not q.empty():
        try:
            result.append(q.get())
        except:
            pass

    for i in result:
        pass
        #print i


def sanitize_command(cmd, name = None):
    # Remove -r for tcpdump/tshark and -I for ngrep
    if "-r" in cmd or "-I" in cmd:
        print "[!] Error, do not use -r or -I to designate a file, use --name"
        sys.exit(1)

    '''
    if name == None:
        cmd = "find " + DRONE_DIR + " -iname '*chunk*' -type f -print0 | xargs -0 -I % " + cmd + " -r %"
    else:
        cmd = "find " + DRONE_DIR + " -iname '*" + name + "*chunk*' -type f -print0 | xargs -0 -I % " + cmd + " -r %"
    '''

    if name == None:
        cmd = "for i in `find " + DRONE_DIR + " | grep 'chunk'`; do " + cmd + " -r $i; done"
    else:
        cmd = "for i in `find " + DRONE_DIR + " | grep '*" + name +"*chunk'`; do " + cmd + " -r $i; done"
    
    return cmd

###
# Load Balancing
###

def load_balance(drone_list, threshold):


    #Populate d.filelist()
    read_existing_files(drone_list)
    
    sum = 0
    for d in drone_list:
        #Get time for file
        sum = sum + d.completiontime

    average = sum / len(drone_list)
    
    slower = []
    faster = []

    for d in drone_list:
        if d.completiontime > average + average * threshold:
            slower.append(d)
        elif d.completiontime < average - average * threshold:
            faster.append(d)

    if len(slower) == 0 or len(faster) == 0:
        return
            
    #These sorts are not going to work
    slower.sort(key=operator.attrgetter("completiontime"), reverse=True)
    faster.sort(key=operator.attrgetter("completiontime"), reverse=False)

    #pdb.set_trace()
        
    # Make lists same size, favoring slower ones
    if len(faster) > len(slower):
        faster = faster[0:len(slower)-1]        
    if len(slower) > len(faster):
        slower = slower[0:len(faster)-1]

    # see if this matches the slowest going to the fastest
    for i in range(len(slower)): 
        ds = slower[i]
        df = faster[i]

        num_files_to_transfer = int(math.ceil((ds.completiontime - average) / ds.time_per_file()))
        shuffle(ds.filelist)

        thread_list = []
        for i in range(num_files_to_transfer):
            t = threading.Thread(target=load_balance_transfer_thread, args = (ds, df, ds.filelist[i]))
            t.daemon = True
            t.start()
            thread_list.append(t)

        for t in thread_list:
            t.join()

            
            
                    
def load_balance_transfer_thread(ds, df, fname):
    #if VERBOSE:
    print "[*] transfering " + fname + " from " + ds.ipaddress + " to " + df.ipaddress
    subprocess.check_call(["rsync", "-avz", "-e", "ssh", ds.ssh_user + "@" + ds.ipaddress + ":" + DRONE_DIR + fname, "/tmp/" + fname], stdout=subprocess.PIPE)

    stdin, stdout, stderr = ds.sshconn.exec_command("rm " + DRONE_DIR + fname)
    
    subprocess.check_call(["rsync", "-avz", "-e", "ssh", "/tmp/" + fname, df.ssh_user + "@" + df.ipaddress + ":" + DRONE_DIR + fname], stdout=subprocess.PIPE)

    subprocess.check_call(["rm", "/tmp/" + fname], stdout=subprocess.PIPE)
    

    df.filelist.append(fname)
    ds.filelist.remove(fname)
    

###
# Deleteing Files
###
    
def clean_drones(drone_list):
    for d in drone_list:
        stdin, stdout, stderr = d.sshconn.exec_command("rm `find " + DRONE_DIR + " | grep 'chunk'`")
    if VERBOSE:
        print "[*] Finished deleting files on drones" 
        
####
# Main 
####
        
def main():
    global VERBOSE
    
    # interface of distribute, command, clear
   
    drone_list = []


    arguments = docopt(usage)

    #print arguments
    
    ssh_user = arguments['--user']

    host_list = []
    if arguments['--config']:
        for i in open(arguments['<configfile>'], 'r').readlines():
            if i.startswith("#"):
                continue
            host_list.append(i.strip())
    else:
        host_list = arguments['--host']
        
    VERBOSE = arguments['--verbose']
    
    for ip in host_list:
        # Create Drone
        drone_list.append(Drone(ip))

    if VERBOSE:
        print "[*] starting drone setup"
    # Threaded setup
    thread_list = []
    for d in drone_list:
        t = threading.Thread(target=setup_drone, args = (d, ssh_user))
        t.daemon = True
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join()

        #d.sshconn = getSSHConn(d, ssh_user)

        #setup(d)

    if VERBOSE:
        print "done with drone setup"


    # Either clean, distribute or command

    if arguments['distribute']:

        file_list = arguments['<pcapfiles>']
        # Prepare captures
        chunked_file_list = create_split(drone_list, file_list)
        transfer_split_files(drone_list, chunked_file_list)
        os.system("rm /Users/irish/Development/ScalablePacketAnalysis/captures/*chunk*")
        
        if VERBOSE:
            print "[*] Finished transfering files to drones"


    if arguments['command']:
        #cmd = "tshark -r /tmp/packet_analysis/*pcap* -T fields -e ip.src -e dns.qry.name -Y 'dns.flags.response eq 0'"

        #if VERBOSE:
            #distributed_files = read_existing_files(drone_list)
            #print "[*] Already distributed files: " + str(distributed_files)
            

        if arguments['--name'] is None:
            cmd = sanitize_command(arguments['<command>'])
        else:
            cmd = sanitize_command(arguments['<command>'], arguments['--name'])

        if VERBOSE:
            print "[*] Sending command to drones: " + cmd

        distribute_command(drone_list, cmd)

        
        if arguments["--balance"]:
            threshold = .10
            if arguments["--balancethreshold"]:
                threshold = arguments["--balancethreshold"] 
            load_balance(drone_list, threshold)
        
        
        
    if arguments['clean']:
        clean_drones(drone_list)
        
        
    # Shut it down
    for d in drone_list:
        d.sshconn.close()


if __name__ == "__main__":
    main()
        
    
