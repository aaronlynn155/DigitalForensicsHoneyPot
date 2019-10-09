import sys
import argparse
import re
import ipaddress
import socket
import datetime

# Converts an IP (IPv4 or IPv6), IP subnet, or hostname to Python's IP address (or network) format depending on what is needed, and handles some possible bad inputs.
def parse_ip(ip, mode='address'):
    try:
        if mode == 'address':
            ip = ipaddress.ip_address(ip)
        if mode == 'network':
            ip = ipaddress.ip_network(ip)   # Will work with individual IPs too as /32, which is needed for storing entries from the whitelist anyhow or else is_ip_authorized() would be more complicated.
    except ValueError:
        try:
            ip = socket.gethostbyname(ip)
        except socket.gaierror:
            print('[ {} ]: \'{}\' could not be resolved to an IP address.'.format(str(datetime.datetime.now()), ip))
            exit(1)
        else:
            ip = ipaddress.ip_address(ip)
    return ip

def parse_port(port):
    if port < 0 or port > 65535:
        print('[ {} ]: \'{}\' is not a valid port number.'.format(str(datetime.datetime.now()), port))
        exit(1)
    return port

# Splits a 'host:post' formatted string (as wanted from the script arguments) in two (to a dictionary) with regular expressions, and handles some possible bad inputs. 
def parse_destination(dest_info_raw):
    dest_info = {}
    try:
        dest_info['host'] = re.findall('^.+(?=:)',   dest_info_raw)[0]
        dest_info['port'] = int(re.findall('(?<=:)\d+$', dest_info_raw)[0])
    except IndexError:
        print('[ {} ]: \'{}\' was not recognized as a valid host:port combination.'.format(str(datetime.datetime.now()), dest_info_raw))
        exit(1)
    dest_info['host'] = parse_ip(dest_info['host'])
    dest_info['port'] = parse_port(dest_info['port'])
    return dest_info

# Opens a file IP and IP subnets and puts the entries into a list that can be iterated, and handles some possible bad inputs.
def parse_whitelist(whitelist_src):
    whitelist = []
    if whitelist_src != None:
        try:
            f = open(whitelist_src, 'r')
        except FileNotFoundError:
            print('[ {} ]: The file given at \'{}\' was not found.'.format(str(datetime.datetime.now()), whitelist_src))
            exit(1)
        except PermissionError:
            print('[ {} ]: Access to the file given at \'{}\' was denied.'.format(str(datetime.datetime.now()), whitelist_src))
            exit(1)
        whitelist = f.read().split('\n')
        for i in range(len(whitelist)):
            whitelist[i] = parse_ip(whitelist[i], mode='network')
    else:
        whitelist = [ipaddress.ip_network('0.0.0.0')]
    return whitelist

# Checks to see if an IP will be allowed through or sent to the honeypot based on how it evaluates against entries in the whitelist (or optionally blacklist)
def is_ip_authorized(ip, whitelist, blacklist_mode=False):
    for entry in whitelist:
        if parse_ip(ip) in entry:
            if not blacklist_mode:
                return True
            else:
                return False
    if not blacklist_mode:
        return False
    else:
        return True

def main():
    description = "This script is one which binds to a port on the local machine and acts as a binary conditional proxy for incoming packets.  " \
                  "When the script receives a packet, it parses a list of IP addresses and subnets to determine where it gets proxied off to.  " \
                  "One way or another, the destination IP and/or port will be changed to something else depending on what the source IP is.  " \
                  "This is to be used as an extra layer of security for valuable ports, which unlike a firewall can be used to redirect unauthorized users to distracting honeypots rather than dropping or rejecting them outright."
    epilog = "Note the effectiveness of this script depends mainly on it running within the host where the valued port is located.  " \
             "This way, the valued port (which has a different port number) can be blocked entirely by the firewall so that only localhost connections are allowed.  " \
             "In turn, this will (or may) require that all connections through that port pass through this script first with the port that it binds to.  " \
             "The honeypot may be on any other host and/or port, assuming it will accept non-localhost connections."
    
    # Here are the script's arguments using the default parsing provided by Python.  This is not the same kind of parsing done by the script, since this parsing only cares that the data types are correct.
    parser = argparse.ArgumentParser(description=description, epilog=epilog)
    parser.add_argument('--port', type=int, required=True, help='local port to bind and listen to')
    parser.add_argument('--real-destination', type=str, default='0.0.0.0:0', help='regular host:port to send whitelisted IP addresses to')
    parser.add_argument('--fake-destination', type=str, default='0.0.0.0:0', help='honeypot host:port to send non-whitelisted IP addresses to')
    parser.add_argument('--whitelist', type=str, help='path to text file of whitelisted IP addresses (newline-delimited)')
    parser.add_argument('--blacklist-mode', action='store_true', help='use whitelist text file to blacklist rather than whitelist IP addresses')
    parser.add_argument('--test-ip', type=str, default='0.0.0.0:0', help='test IP to evaluate against is_ip_authorized(); REMOVE BY FINAL VERSION')
    args = parser.parse_args()

    # Now for the script's own parsing and error-checking...
    port             = parse_port(args.port)
    real_destination = parse_destination(args.real_destination)
    fake_destination = parse_destination(args.fake_destination)
    whitelist        = parse_whitelist(args.whitelist)
    
    # Argument tests to prove current script (i.e. parsing) is working as it should.  Also a placeholder for proxy functions until they get done, after which this block will be removed.
    print('\nPort: {}'.format(port))
    print('\nReal Destination: {}'.format(real_destination))
    print('\nFake Destination: {}'.format(fake_destination))
    print('\nWhitelist: {}'.format(whitelist))
    print('\nBlacklist? {}'.format(args.blacklist_mode))
    test_ip_result = is_ip_authorized(args.test_ip, whitelist, blacklist_mode=args.blacklist_mode)
    print('\nTest IP Authorized? {}\n'.format(test_ip_result))
    
    # >>> PROXY TOMFOOLERY GOES HERE <<<
    
    exit(0)

main()