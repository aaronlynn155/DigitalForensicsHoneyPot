import sys
import argparse
import re
import ipaddress
import socket
import threading
import datetime

class Connection:
    def __init__(self, client, buffer_size=4096):
        self.client_socket, self.client_ipport = client
        self.buffer_size                       = buffer_size
    
    def bridge(self, server_ipport):
        self.server_ipport = server_ipport
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except:
            print('[ {} ]: Failed to create socket for server at {}:{}.'.format(str(datetime.datetime.now()), self.server_ipport[0], self.server_ipport[1]))
            self.client_socket.close()
            raise
        try:
            self.server_socket.connect(self.server_ipport)
        except:
            print('[ {} ]: Failed to connect to server at {}:{}.'.format(str(datetime.datetime.now()), self.server_ipport[0], self.server_ipport[1]))
            self.client_socket.close()
            raise
    
    def open(self):
        self.client_listener = threading.Thread(target=self.__handler, args=(self.client_socket, self.client_ipport, self.server_socket, self.server_ipport, True))
        self.server_listener = threading.Thread(target=self.__handler, args=(self.server_socket, self.server_ipport, self.client_socket, self.client_ipport, False))
        self.client_listener.start()
        self.server_listener.start()
    
    def __handler(self, source_socket, source_ipport, destination_socket, destination_ipport, is_client):
        try:
            while True:
                data = source_socket.recv(self.buffer_size)
                if not data:
                    break
                destination_socket.send(data)
        except ConnectionResetError:
            if is_client:
                print('[ {} ]: Client at {} disconnected from server at {}:{}.'.format(str(datetime.datetime.now()), source_ipport[0], destination_ipport[0], destination_ipport[1]))
            else:
                print('[ {} ]: Server at {}:{} disconnected from client at {}.'.format(str(datetime.datetime.now()), source_ipport[0], source_ipport[1], destination_ipport[0]))
        except ConnectionAbortedError:
            pass
        self.close()
    
    def close(self):
        self.client_socket.close()
        self.server_socket.close()

class Server:
    def __init__(self, proxy_port, real_destination, fake_destination, whitelist, blacklist_mode, localhost_mode=False):
        try:
            self.proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except:
            print('[ {} ]: Failed to create socket for script.'.format(str(datetime.datetime.now())))
            exit(1)
        
        if localhost_mode:
            self.proxy_ipport = ('127.0.0.1', proxy_port)
        else:
            self.proxy_ipport = (socket.gethostbyname(socket.gethostname()), proxy_port)
        
        self.real_destination = real_destination
        self.fake_destination = fake_destination
        self.whitelist        = whitelist
        self.blacklist_mode   = blacklist_mode

    def start(self):
        try:
            self.proxy_socket.bind(self.proxy_ipport)
        except:
            print('[ {} ]: Could not bind script to port {}; check that it is not in use already.'.format(str(datetime.datetime.now()), self.proxy_ipport[1]))
            exit(1)
        self.proxy_socket.listen(5)
        self.listener = threading.Thread(target=self.__handler)
        self.listener.start()
    
    def __handler(self):
        while True:
            client_socket, client_ipport = self.proxy_socket.accept()
            connection = Connection((client_socket, client_ipport))
            if self.__is_ip_authorized(client_ipport[0]):
                print('[ {} ]: Authorized client at {} connected, forwarded to {}:{}.'.format(str(datetime.datetime.now()), client_ipport[0], self.real_destination[0], self.real_destination[1]))
                try:
                    connection.bridge(self.real_destination)
                except:
                    continue
            else:
                print('[ {} ]: Unauthorized client at {} connected, forwarded to {}:{}.'.format(str(datetime.datetime.now()), client_ipport[0], self.fake_destination[0], self.fake_destination[1]))
                try:
                    connection.bridge(self.fake_destination)
                except:
                    continue
            connection.open()
        self.close()

    def close(self):
        self.proxy_socket.close()

    # Checks to see if an IP will be allowed through or sent to the honeypot based on how it evaluates against entries in the whitelist (or optionally blacklist)
    def __is_ip_authorized(self, ip):
        for entry in self.whitelist:
            if parse_ip(ip) in entry:
                if not self.blacklist_mode:
                    return True
                else:
                    return False
        if not self.blacklist_mode:
            return False
        else:
            return True

# Converts an IP (IPv4 or IPv6), IP subnet, or hostname to Python's IP address (or network) format depending on what is needed, and handles some possible bad inputs.
def parse_ip(ip, mode='address'):
    try:
        if mode == 'address':
            ip = ipaddress.ip_address(ip)
        if mode == 'network':
            ip = ipaddress.ip_network(ip)   # Will work with individual IPs too as /32, which is needed for storing entries from the whitelist anyhow or else is_ip_authorized() would be more complicated.
    except ValueError:
        if ip:
            try:
                ip = socket.gethostbyname(ip)
                ip = ipaddress.ip_address(ip)
            except:
                print('[ {} ]: \'{}\' could not be resolved to an IP address.'.format(str(datetime.datetime.now()), ip))
                ip = None
        else:
            ip = None
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
        dest_info['port'] = re.findall('(?<=:)\d+$', dest_info_raw)[0]
    except IndexError:
        print('[ {} ]: \'{}\' was not recognized as a valid host:port combination.'.format(str(datetime.datetime.now()), dest_info_raw))
        exit(1)
    dest_info['host'] = parse_ip(dest_info['host'])
    if dest_info['host'] is None:
        exit(1)
    dest_info['host'] = str(dest_info['host'])
    dest_info['port'] = parse_port(int(dest_info['port']))
    return (dest_info['host'], dest_info['port'])

# Opens a file IP and IP subnets and puts the entries into a list that can be iterated, and handles some possible bad inputs.
def parse_whitelist(whitelist_src):
    whitelist         = []
    whitelist_cleaned = []
    if whitelist_src != None:
        try:
            f = open(whitelist_src, 'r')
        except FileNotFoundError:
            log('The file given at \'{}\' was not found.'.format(whitelist_src))
            exit(1)
        except PermissionError:
            log('Access to the file given at \'{}\' was denied.'.format(whitelist_src))
            exit(1)
        whitelist = f.read().split('\n')
        for i in range(len(whitelist)):
            entry = parse_ip(whitelist[i], mode='network')
            if entry is not None:
                whitelist_cleaned.append(entry)
        if not whitelist_cleaned:
            whitelist_cleaned = [ipaddress.ip_network('0.0.0.0')]
    else:
        whitelist_cleaned = [ipaddress.ip_network('0.0.0.0')]
    return whitelist_cleaned

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
    
    server_localhost = Server(port, real_destination, fake_destination, whitelist, args.blacklist_mode, localhost_mode=True)
    server           = Server(port, real_destination, fake_destination, whitelist, args.blacklist_mode, localhost_mode=False)
    server_localhost.start()
    server.start()
    
    exit(0)

main()