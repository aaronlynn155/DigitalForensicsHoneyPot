import sys
import argparse
import re
import ipaddress
import socket
import datetime
import time

description = "This script is one which binds to a port on the local machine and acts as a binary conditional proxy for incoming packets.  " \
              "When the script receives a packet, it parses a list of IP addresses and subnets to determine where it gets proxied off to.  " \
              "One way or another, the destination IP and/or port will be changed to something else depending on what the source IP is.  " \
              "This is to be used as an extra layer of security for valuable ports, which unlike a firewall can be used to redirect unauthorized users to distracting honeypots rather than dropping or rejecting them outright."
epilog = "Note the effectiveness of this script depends mainly on it running within the host where the valued port is located.  " \
         "This way, the valued port (which has a different port number) can be blocked entirely by the firewall so that only localhost connections are allowed.  " \
         "In turn, this will (or may) require that all connections through that port pass through this script first with the port that it binds to.  " \
         "The honeypot may be on any other host and/or port, assuming it will accept non-localhost connections."

parser = argparse.ArgumentParser(description=description, epilog=epilog)
parser.add_argument('--port', type=int, required=True, help='local port to bind and listen to')
parser.add_argument('--real-destination', type=str, default='0.0.0.0:0', help='regular host:port to send whitelisted IP addresses to')
parser.add_argument('--fake-destination', type=str, default='0.0.0.0:0', help='honeypot host:port to send non-whitelisted IP addresses to')
parser.add_argument('--whitelist', type=str, help='path to text file of whitelisted IP addresses (newline-delimited)')
parser.add_argument('--blacklist-mode', action='store_true', help='use whitelist text file to blacklist rather than whitelist IP addresses')
args = parser.parse_args()

def close():
    sleep_time = 5
    print('[ {} ]: This script will close in {} seconds.'.format(str(datetime.datetime.now()), sleep_time))
    time.sleep(sleep_time)
    exit()
    
def parse_ip(ip, mode='address'):
    try:
        if mode == 'address':
            ip = ipaddress.ip_address(ip)
        if mode == 'network':
            ip = ipaddress.ip_network(ip)
    except ValueError:
        try:
            ip = socket.gethostbyname(ip)
        except socket.gaierror:
            print('[ {} ]: \'{}\' could not be resolved to an IP address.'.format(str(datetime.datetime.now()), ip))
            close()
        else:
            ip = ipaddress.ip_address(ip)
    return ip

def parse_destinations(dest_info_raw):
    dest_info = []
    for dest in dest_info_raw:
        try:
            dest_host = re.findall('^.+(?=:)',   dest)[0]
            dest_port = re.findall('(?<=:)\d+$', dest)[0]
        except IndexError:
            print('[ {} ]: \'{}\' was not recognized as a valid host:port combination.'.format(str(datetime.datetime.now()), dest))
            close()
        dest_host = parse_ip(dest_host)
        dest_info.append(dest_host)
        dest_info.append(dest_port)
    return dest_info

def parse_whitelist(whitelist_src):
    whitelist = []
    f = open(whitelist_src, 'r')
    whitelist = f.read().split('\n')
    for i in range(len(whitelist)):
        if re.match('^.+/\d+$', whitelist[i]):
            whitelist[i] = parse_ip(whitelist[i], mode='network')
        else:
            whitelist[i] = parse_ip(whitelist[i], mode='address')
    return whitelist

def main():
    dest_info = parse_destinations((args.real_destination, args.fake_destination))
    if args.whitelist != None:
        whitelist = parse_whitelist(args.whitelist)
    else:
        whitelist = [ipaddress.ip_address('0.0.0.0')]
    print('\n{}'.format(dest_info))
    print('\n{}'.format(whitelist))

#s = socket.socket()
#host = socket.gethostname()
#port = args.port
#s.bind((host, port))

main()
exit()