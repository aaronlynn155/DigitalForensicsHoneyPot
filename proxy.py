import sys
import argparse
import re
import ipaddress
import socket
import threading
import datetime
import os

# This is a static class used throughout the script for logging, both to files and to stdout.
# It being static, of course, just means it's usable without passing around an object, which is my logic behind choosing to do it this way.
class Logger:
    is_logging_disabled = False
    log_folder          = None

    # If and when attempting to use the given log folder, the script must first check if it can, either by creating it if it doesn't exist or having permission if it does.
    # If not either, the script's own directory is used.
    # Likewise, it is assumed by the script that it has permissions to write to its own directory.
    @classmethod
    def parse_log_folder(cls, log_folder):
        if cls.is_logging_disabled:
            return
    
        if log_folder is None:
            return
        
        if not os.path.isdir(log_folder):
            try:
                os.makedirs(log_folder)
            except:
                cls.log('Failed to locate or create the log directory \'{}\'; script path will be used instead.'.format(log_folder))
                return
        
        # The class assumes the proper permissions based on whether it can create a test file in the given directory.
        testfile = os.path.join(log_folder, 'testfile.testfile')
        try:
            f = open(testfile, 'w')
        except PermissionError:
            cls.log('Access to the given log directory \'{}\' was denied; script path will be used instead.'.format(log_folder))
        else:
            f.close()
            os.remove(testfile)
            
            cls.log_folder = log_folder
            return
    
    # Most methods here call this function in place of print() or something like that to output to the screen as well as to log files, which are optional.
    # In most cases, this method will also be what exits the script in case of an unrecoverable exception.
    # In other words, it's the default exception handler.
    @classmethod
    def log(cls, message, is_fatal=False):
        full_message = '[ {} ]: {}'.format(str(datetime.datetime.now()), message)
        
        print(full_message)
        
        if cls.is_logging_disabled:
            return
        
        # The name of the log file is determined here instead of in parse_log_folder() due to the date being a part of the log's file-naming convention.
        # If the script ran for multiple days, that would of course be a problem, since parse_log_folder() is only run when the script first starts up.
        fname = 'log-{}.txt'.format(str(datetime.date.today()))
        if cls.log_folder is None:
            path = os.path.join(fname)
        else:
            path = os.path.join(cls.log_folder, fname)
            
        f = open(str(path), 'a')
        f.write('{}\n'.format(full_message))
        
        if (is_fatal):
            fatal_error = '[ {} ]: A fatal error has occurred.'.format(str(datetime.datetime.now()))
            print(fatal_error)
            f.write('{}\n'.format(fatal_error))
            exit(1)
        
        f.close()

# In terms of how it's defined here, a 'Connection' object is actually meant to represent two connections: one between the client and the proxy server, and one between the proxy server and the client's destination.
# As a TCP proxy, the server is meant to forward traffic from one to the other, and because of this codependency, this class exists to abstract the two connections so that they're treated as one going from client to destination.
class Connection:
    def __init__(self, client, buffer_size=4096):
        self.client_socket, self.client_ipport = client
        self.buffer_size                       = buffer_size
    
    # This attempts to establish a connection with the destination, as well as the more abstract "Connection" between the client and the destination done over the proxy.
    # The use of two threads is to prevent one connection from blocking the other while it is listened for (in other words, so they aren't forced to take turns), so each side can send and receive asynchronously.
    # This is needed for many protocols like SSH to work in that they may send multiple packets at a time.
    def bridge(self, server_ipport):
        self.server_ipport = server_ipport
        
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except:
            Logger.log('Failed to create socket for server at {}:{}.'.format(self.server_ipport[0], self.server_ipport[1]))
            self.client_socket.close()
            raise
        try:
            self.server_socket.connect(self.server_ipport)
        except:
            Logger.log('Failed to connect to server at {}:{}.'.format(self.server_ipport[0], self.server_ipport[1]))
            self.client_socket.close()
            raise
    
        self.client_listener = threading.Thread(target=self.__handler, args=(self.client_socket, self.client_ipport, self.server_socket, self.server_ipport, True))
        self.server_listener = threading.Thread(target=self.__handler, args=(self.server_socket, self.server_ipport, self.client_socket, self.client_ipport, False))
        self.client_listener.start()
        self.server_listener.start()
    
    # Handles the forwarding of packets from one side to the other.
    # Notice that it is not bidirectional, and a second thread running this function in the opposite direction is required for bidirectional communication to occur.
    def __handler(self, source_socket, source_ipport, destination_socket, destination_ipport, is_client):
        try:
            while True:
                data = source_socket.recv(self.buffer_size)
                if not data:
                    break
                destination_socket.send(data)
        except ConnectionResetError:
            if is_client:
                Logger.log('Client at {} disconnected from server at {}:{}.'.format(source_ipport[0], destination_ipport[0], destination_ipport[1]))
            else:
                Logger.log('Server at {}:{} disconnected from client at {}.'.format(source_ipport[0], source_ipport[1], destination_ipport[0]))
        except ConnectionAbortedError:
            pass # A ConnectionAbortedError is expected from the other thread after a ConnectionResetError occurs.  In that case, it would be redundant to display a message for it.
            
        # Because these threads are not tracked elsewhere, they're required to close themselves at the end of their run when the connection is disrupted for whatever reason.
        self.close()
    
    # Since they are codependent, of course it makes sense that one connection going down forces the other to go down as well, if this larger 'Connection' should behave like a singular connection.
    def close(self):
        self.client_socket.close()
        self.server_socket.close()

# This simple server class just acts as a TCP proxy for clients that connect to whatever port it binds to.  However, their destination is determined by how they're authorized by the server and the whitelist.
# The server can maintain multiple 'connections' at once.
class Server:
    def __init__(self, proxy_port, real_destination, fake_destination, whitelist, blacklist_mode, localhost_mode=False):
        try:
            self.proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except:
            Logger.log('Failed to create socket for script.', is_fatal=True)
        
        # "Localhost mode" exists since I discovered that the server won't listen on localhost *just* from it already listening on its IP address.
        # Ultimately, this requires two Server objects/threads since, of course, one can't listen on both that and its actual IP at the same time regardless.
        if localhost_mode:
            self.proxy_ipport = ('127.0.0.1', proxy_port)
        else:
            self.proxy_ipport = (socket.gethostbyname(socket.gethostname()), proxy_port)
        
        self.real_destination = real_destination
        self.fake_destination = fake_destination
        self.whitelist        = whitelist
        self.blacklist_mode   = blacklist_mode

    # Turns the proxy server on and creates a thread for it.
    def start(self):
        try:
            self.proxy_socket.bind(self.proxy_ipport)
        except:
            Logger.log('Could not bind script to port {}; check that it is not in use already.'.format(self.proxy_ipport[1]), is_fatal=True)
        self.proxy_socket.listen(5)
        
        self.listener = threading.Thread(target=self.__handler)
        Logger.log('Reverse proxy server started listening on {}:{}.'.format(self.proxy_ipport[0], self.proxy_ipport[1]))
        self.listener.start()
    
    # This method represents the primary proxy server thread.  The script will normally run 2 for localhost and the server IP respectively.
    # This continually receives clients, judges their authorization rights against the whitelist, and generates a 'connection' between them and the destination they're sent to that the script maintains.
    # Multiple clients may be received or handled simultaneously.
    def __handler(self):
        while True:
            client_socket, client_ipport = self.proxy_socket.accept()
            connection = Connection((client_socket, client_ipport))
            
            if self.__is_ip_authorized(client_ipport[0]):
                Logger.log('Authorized client at {} connected, forwarded to {}:{}.'.format(client_ipport[0], self.real_destination[0], self.real_destination[1]))
                try:
                    connection.bridge(self.real_destination)
                except:
                    continue # If for some reason, a connection to the destination doesn't work, just let the server continue running for other clients, and in case it becomes available again.
            else:
                Logger.log('Unauthorized client at {} connected, forwarded to {}:{}.'.format(client_ipport[0], self.fake_destination[0], self.fake_destination[1]))
                try:
                    connection.bridge(self.fake_destination)
                except:
                    continue
        
        # Like each 'connection', the server thread can only close itself once an exception occurs.
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
# Does not fail and returns None since some use cases here are recoverable.
def parse_ip(ip, mode='address'):
    try:
        if mode == 'address':
            ip = ipaddress.ip_address(ip)
        if mode == 'network':
            ip = ipaddress.ip_network(ip) # Will work with individual IPs too as /32, which is needed for storing entries from the whitelist anyhow or else is_ip_authorized() would be more complicated.
    except ValueError:
        if ip:
            try:
                ip = socket.gethostbyname(ip) # Attempts DNS resolution
                ip = ipaddress.ip_address(ip)
            except:
                Logger.log('\'{}\' could not be resolved to an IP address.'.format(ip))
                ip = None
        else:
            ip = None
    
    return ip

def parse_port(port):
    try:
        port = int(port)
    except ValueError:
        Logger.log('\'{}\' is not a valid port number.'.format(port), is_fatal=True)
    
    if port < 0 or port > 65535:
        Logger.log('\'{}\' is not a valid port number.'.format(port), is_fatal=True)
    
    return port

# Splits a 'host:post' formatted string (as desired by the script arguments) in two (to a dictionary) with regular expressions, and handles some possible bad inputs. 
def parse_destination(dest_info_raw):
    dest_info = {}
    
    try:
        dest_info['host'] = re.findall('^.+(?=:)',   dest_info_raw)[0]
        dest_info['port'] = re.findall('(?<=:)\d+$', dest_info_raw)[0]
    except IndexError:
        Logger.log('\'{}\' was not recognized as a valid host:port combination.'.format(dest_info_raw), is_fatal=True)
    
    temp = parse_ip(dest_info['host'])
    if temp is None:
        Logger.log('\'{}\' was not recognized as a valid host.'.format(dest_info['host']), is_fatal=True)
    dest_info['host'] = str(temp)
    
    dest_info['port'] = parse_port(dest_info['port'])
    
    # Returns the ('ip', port) tuple format that other Python libraries typically use for host:port combinations.
    return (dest_info['host'], dest_info['port'])

# Opens a file IP and IP subnets and puts the entries into a list that can be iterated, and handles some possible bad inputs.
def parse_whitelist(whitelist_src):
    whitelist         = []
    whitelist_cleaned = []
    
    if whitelist_src != None:
        try: # The script will work without an explicit whitelist file, though if one appears intended, it is fail-fast regardless.
            f = open(whitelist_src, 'r')
        except FileNotFoundError:
            Logger.log('The file given at \'{}\' was not found.'.format(whitelist_src), is_fatal=True)
        except PermissionError:
            Logger.log('Access to the file given at \'{}\' was denied.'.format(whitelist_src), is_fatal=True)
            
        whitelist = f.read().split('\n')
        for i in range(len(whitelist)):
            entry = parse_ip(whitelist[i], mode='network')
            if entry is not None: # Empty lines and other odd lines/entries are ignored
                whitelist_cleaned.append(entry)
        
        # If there's no valid entries or just no whitelist given at all, a default 0.0.0.0 is assumed as a (usually) failsafe placeholder to logically imply an empty list to the rest of the script.
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
    parser.add_argument('--log-folder', type=str, default=None, help='path to directory for containing log entries')
    parser.add_argument('--disable-logging', action='store_true', help='prevents creation and modification of log files')
    args = parser.parse_args()

    # Now for the script's own parsing and error-checking...
    port             = parse_port(args.port)
    real_destination = parse_destination(args.real_destination)
    fake_destination = parse_destination(args.fake_destination)
    whitelist        = parse_whitelist(args.whitelist)
    
    Logger.is_logging_disabled = args.disable_logging
    Logger.parse_log_folder(args.log_folder)
    
    # Most of the magic is done here.
    # Two server threads are needed if we want the server to listen on both localhost and from the outside.
    server_localhost = Server(port, real_destination, fake_destination, whitelist, args.blacklist_mode, localhost_mode=True)
    server           = Server(port, real_destination, fake_destination, whitelist, args.blacklist_mode, localhost_mode=False)
    server_localhost.start()
    server.start()
    
    exit(0)

main()