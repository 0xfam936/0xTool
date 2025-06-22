import signal
import os
import platform
import socket
import psutil
import ipaddress
import re
import string
import itertools
import tqdm
from colorama import Fore
from time import sleep
class return_to_menu(Exception):
    pass
class exit_program(Exception):
    pass
class exit_handler: # Ovewrite user interuption handling
    def after_exit(self,sig,frame):
        print(f"\n[{Fore.RED}!{Fore.RESET}] Interrupt received. Returning to menu...")
        sleep(2)
        raise return_to_menu
    def start(self):
        signal.signal(signal.SIGINT,self.after_exit)
class console_handler:
    def __init__(self,OS:str=None):
        self.OS =  device_info().get_OS() if OS is None else OS
    def clear(self): # Clear console
        if self.OS == "windows":
            os.system("cls")
        else:
            os.system("clear")
    def banner(self,title:str,padding:int=5): # Generate banner with the given string and padding
        TITLE = title.upper()
        print("#" * (len(TITLE) + padding * 2))
        print(" " * padding + TITLE)
        print("#" * (len(TITLE) + padding * 2))
class device_info:
    def get_OS(self) -> str: # Get device OS
        return platform.system().lower()
    def get_IP(self)->str: # Get device IP
        SOCK = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        try:
            SOCK.connect(("8.8.8.8",80))
            IP = SOCK.getsockname()[0]
        finally:
            SOCK.close()
        return IP
    def get_NIC_info(self,IP:str)-> dict: # GET device NIC info
        INTERFACE = psutil.net_if_addrs()
        for iface,addrs in INTERFACE.items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == IP:
                    netmask = addr.netmask
                    prefix = ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
                    return{
                        "interface":iface,
                        "IP":IP,
                        "netmask":netmask,
                        "prefix":prefix,
                        "cidr":f"{IP}/{prefix}"
                    }
        return None
    def get_MAC_by_IP(self, ip_address: str = None) -> str: # Get MAC of the given IP if not found return None
        if ip_address is None:
            ip_address = self.get_IP()
        interfaces = psutil.net_if_addrs()
        for interface_name, addrs in interfaces.items():
            ip = None
            mac = None
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    if addr.address == ip_address:
                        ip = addr.address
                elif addr.family == psutil.AF_LINK:
                    mac = addr.address
            if ip and mac:
                return mac
        return None
class validate_network_info:
    def is_valid_IP(self,IP:str)-> bool: # Validate the given IP address
            try:
                ipaddress.ip_address(IP)
                return True
            except:
                return False
    def is_valid_cidr(self,cidr:str)-> bool: # Validate the cidr format
        try:
            NETWORK = ipaddress.ip_network(cidr,strict=False)
            return True
        except:
            return False
    def is_valid_MAC(self,mac:str)-> bool: # Validate MAC format
        MAC_PATTERN = re.compile(r'^([0-9A-Fa-f]{2}[:\-]?){5}[0-9A-Fa-f]{2}$')
        return bool(MAC_PATTERN.match(mac))
