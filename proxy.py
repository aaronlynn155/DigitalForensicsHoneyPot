import sys
import argparse
import re
import ipaddress
import socket
import threading
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
        except:
            print('[ {} ]: \'{}\' could not be resolved to an IP address.'.format(str(datetime.datetime.now()), ip))
            exit(1)
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

def handler(source_socket, destination_socket, buffer_size=4096):
    try:
        while True:
            data = source_socket.recv(buffer_size)
            if not data:
                break
            destination_socket.send(data)
    except:
        print('[ {} ]: Client at IP address {} disconnected.'.format(str(datetime.datetime.now()), 'PLACEHOLDER'))

def forward(client_socket, server_info):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((str(server_info['host']), server_info['port']))
    client_listen = threading.Thread(target=handler, args=(client_socket, server_socket))
    server_listen = threading.Thread(target=handler, args=(server_socket, client_socket))
    client_listen.start()
    server_listen.start()
    client_listen.join()
    server_listen.join()
    client_socket.close()
    server_socket.close()

def server(port, real_destination, fake_destination, whitelist, blacklist_mode):
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy        = socket.gethostname()
    source_info  = {}
    
    try:
        proxy_socket.bind((proxy, port))
    except:
        print('[ {} ]: Could not bind script to port {}; check that it is not in use already.'.format(str(datetime.datetime.now()), port))
        exit(1)
    proxy_socket.listen(5)
    while True:
        client_socket, source = proxy_socket.accept()
        source_info['host'], source_info['port'] = source
        if is_ip_authorized(source_info['host'], whitelist, blacklist_mode):
            print('[ {} ]: Authorized client at IP address {} connected, forwarded to {}:{}.'.format(str(datetime.datetime.now()), source_info['host'], real_destination['host'], real_destination['port']))
            proxy_thread = threading.Thread(target=forward, args=(client_socket, real_destination))
        else:
            print('[ {} ]: Unauthorized client at IP address {} connected, forwarded to {}:{}.'.format(str(datetime.datetime.now()), source_info['host'], fake_destination['host'], fake_destination['port']))
            proxy_thread = threading.Thread(target=forward, args=(client_socket, fake_destination))
        proxy_thread.start()
    proxy_socket.close()

def main():
    DESCRIPTION = "This script is one which binds to a port on the local machine and acts as a binary conditional proxy for incoming packets.  " \
                  "When the script receives a packet, it parses a list of IP addresses and subnets to determine where it gets proxied off to.  " \
                  "One way or another, the destination IP and/or port will be changed to something else depending on what the source IP is.  " \
                  "This is to be used as an extra layer of security for valuable ports, which unlike a firewall can be used to redirect unauthorized users to distracting honeypots rather than dropping or rejecting them outright."
    EPILOG = "Note the effectiveness of this script depends mainly on it running within the host where the valued port is located.  " \
             "This way, the valued port (which has a different port number) can be blocked entirely by the firewall so that only localhost connections are allowed.  " \
             "In turn, this will (or may) require that all connections through that port pass through this script first with the port that it binds to.  " \
             "The honeypot may be on any other host and/or port, assuming it will accept non-localhost connections."
    
    # Here are the script's arguments using the default parsing provided by Python.  This is not the same kind of parsing done by the script, since this parsing only cares that the data types are correct.
    parser = argparse.ArgumentParser(description=DESCRIPTION, epilog=EPILOG)
    parser.add_argument('--port', type=int, required=True, help='local port to bind and listen to')
    parser.add_argument('--real-destination', type=str, default='0.0.0.0:0', help='regular host:port to send whitelisted IP addresses to')
    parser.add_argument('--fake-destination', type=str, default='0.0.0.0:0', help='honeypot host:port to send non-whitelisted IP addresses to')
    parser.add_argument('--whitelist', type=str, help='path to text file of whitelisted IP addresses (newline-delimited)')
    parser.add_argument('--blacklist-mode', action='store_true', help='use whitelist text file to blacklist rather than whitelist IP addresses')
    args = parser.parse_args()

    # Now for the script's own parsing and error-checking...
    port             = parse_port(args.port)
    real_destination = parse_destination(args.real_destination)
    fake_destination = parse_destination(args.fake_destination)
    whitelist        = parse_whitelist(args.whitelist)
    
    server(port, real_destination, fake_destination, whitelist, args.blacklist_mode)
    
    exit(0)

main()