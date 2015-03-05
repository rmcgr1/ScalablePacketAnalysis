#!/usr/bin/python
import paramiko
import sys
import os


CAPTURE_DIR = "./captures"


class Drone:
    def __init__(self, ipaddress):
        self.ipaddress = ipaddress
        self.freespace = None
        self.sshconn = None

'''
TODO:

distribute cap files
send tshark command
recieve result
error handling
'''

def setup(d):
    # See if the right programs are installed
    needed_programs = ['tshark', 'editcap', 'ngrep', 'rsync']
    
    for i in needed_programs:
        stdin, stdout, stderr = d.sshconn.exec_command("which " + i)
        if i not in stdout.read():
            print "[!] Error " + i + " not installed on " + str(d)

    # Make working directory
    stdin, stdout, stderr = d.sshconn.exec_command("mkdir -p /tmp/packet_analysis")

    # Get Available Space
    stdin, stdout, stderr = d.sshconn.exec_command("df /tmp | tail -n +2 | awk '{print$4}'")
    d.freespace = int(stdout.read())


def getSSHConn(d):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(d.ipaddress, username='user', password='')
    except paramiko.AuthenticationException:
        print "Authentication failed when connecting to " + str(d.ipaddress)
        raise
    except:
        print "Could not SSH to waiting for it to start" + str(d.ipaddress)
        raise
    return ssh

def create_split(drone_list):
    file_list = []
    for file in os.listdir(CAPTURE_DIR):
        if file.endswith(".pcap"):
            file_list.append(file)

    # Compute split size
    total_file_size = 0
    for i in file_list:
        total_file_size = total_file_size + os.path.getsize(i)

    # See if the size is OK with taking up no more than 85% of available free space on the least free drone
    least_free_space = sys.maxint
    for d in drone_list:
        if least_free_space < d.freespace:
            least_free_space = d.freespace
    least_free_space = least_free_space * .85
    number_of_drones = len(drone_list)

    print str(least_free_space)
    
    if total_file_size / number_of_drones < least_free_space:
        # Good to go
        pass
    
    else:
        print "[!] Error: not enough free space on drones"
        print "TODO handle this"
        


def main():
    
    host_list = ['192.168.2.100', '192.168.2.101', '192.168.2.102', '192.168.2.103']
    drone_list = []

    for ip in host_list:
        # Create Drone
        drone_list.append(Drone(ip))
        
    for d in drone_list:
        d.sshconn = getSSHConn(d)        
        setup(d)

    # Prepare captures
    create_split(drone_list)

    
    # Shut it down
    for d in drone_list:
        d.sshconn.close()


if __name__ == "__main__":
    main()
        
    
