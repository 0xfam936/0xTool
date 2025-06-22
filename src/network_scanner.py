import scapy.all as sc
from colorama import Fore, init, Style
from socket import gethostbyaddr
class netscan:
    def __init__(self,IP_range:str,MAC_range:str,packet_timeout_begin:int=1,packet_timeout_end:int=10,verbose:bool=False):
        init(autoreset=True) # Reset syle after every colorama use
        self.IP_range=IP_range
        self.MAC_range=MAC_range
        self.packet_timeout_begin=packet_timeout_begin
        self.packet_timeout_end=packet_timeout_end
        self.verbose=verbose
        self.device_list=[]        
    def start(self):
        print(f"{Fore.BLUE + Style.BRIGHT}{"name":<50}{Fore.GREEN}{"IPv4":<20}{Fore.YELLOW}MAC") # Shows the name, IP and the MAC title in a formatted way
        print("-"*90) # Shows "-" 90 times
        for timeout in range (self.packet_timeout_begin,self.packet_timeout_end):
            self.handle_ARP_scan(timeout) # Starts the ARP scan with the given timeout
    def ARP_scan(self,time:int) -> list:
        packet = sc.Ether(dst=self.MAC_range)/sc.ARP(pdst=self.IP_range) # Makes frames for ARP requests
        answered, _ = sc.srp(packet,timeout=time,verbose=self.verbose) # Send ARP requests to the given network range using the packet
        return answered # Returns devices 
    def handle_ARP_scan(self,time:int)->None:
        devices = self.ARP_scan(time) # Devices list that have reacted to the ARP request
        for device in devices: # Goes through every device on the list
            IP=device[1].psrc # Source IP
            MAC=device[1].hwsrc # Source MAC
            name = self.get_host_name(IP) # Gets device name
            if not any(IP == device["IP"] for device in self.device_list): # Check if the device is already in the list or not
                self.show_scan_results(name,IP,MAC) # Show the results in a formatted manner if not in list
                self.device_list.append({"name":name,"IP":IP,"MAC":MAC}) # Appends the devices to a list if not in list
    def get_host_name(self,IP:str) -> str:
        try:
            return gethostbyaddr(IP)[0] # Returns hostname using IP if possible
        except:
            for _ in range(2):
                try:
                    return gethostbyaddr(IP)[0] # Tries 2 times to return hostname using IP if possible
                except:
                    continue
            return "UNKNOWN" # Returns UNKNOWN if the hostname cannot be received using IP
    def show_scan_results(self,name:str,IP:str,MAC:str) -> None:
        print(f"{Fore.BLUE}{name:<50}{Fore.GREEN}{IP:<20}{Fore.YELLOW}{MAC}") # Shows the name, IP and the MAC in a formatted way
        print("-"*90) # Shows "-" 90 times
