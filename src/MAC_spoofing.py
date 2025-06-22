import subprocess
import helper_functions
import random
from colorama import Fore, init

class MAC_spoof:
    def __init__(self, change_mac_to: str = None, IP: str = None):
        self.OS = helper_functions.device_info().get_OS() # Get the OS
        # If no valid MAC given change MAC to random otherwise change MAC to given
        self.CHANGE_MAC_TO = (
            change_mac_to
            if change_mac_to and helper_functions.validate_network_info().is_valid_MAC(change_mac_to)
            else self.generate_random_mac()
        )
        self.IP = IP or helper_functions.device_info().get_IP() # Get IP of the internet connected NIC
        self.ORIGINAL_MAC = helper_functions.device_info().get_MAC_by_IP(self.IP) # ORIGINAL MAC
        self.ORIGINAL_NIC_INFO = helper_functions.device_info().get_NIC_info(self.IP) # ORIGINAL NIC INFO
        self.NEW_MAC = None # New MAC not set yet
        self.CHANGED_NIC_info = None # Changed/Unchanged NIC info not set yet
        init(autoreset=True) # Color auto reset after printing the banner 
    def change_mac(self):
        # Check the OS for the MAC changing
        if self.OS == "windows":
            self.change_windows_mac()
        else:
            self.change_Linux_mac()
        self.CHANGED_NIC_info = helper_functions.device_info().get_NIC_info(self.IP) # Get the NIC info after changing MAC
        self.NEW_MAC = helper_functions.device_info().get_MAC_by_IP(self.IP) # Get MAC info after changing
        self.show_old_and_new_mac() # Show the old and new data
    def show_old_and_new_mac(self):
        # Show the results formatted
        print(
            f"[{Fore.GREEN}ORIGINAL{Fore.RESET}] {self.ORIGINAL_MAC:<20}{'    ======>':<20}"
            f"[{self.get_status(self.NEW_MAC,self.ORIGINAL_MAC)}] {self.NEW_MAC:<30}"
        )
        print(
            f"[{Fore.GREEN}ORIGINAL{Fore.RESET}] {self.ORIGINAL_NIC_INFO['IP']:<20}{'    ======>':<20}"
            f"[{self.get_status(self.CHANGED_NIC_info['IP'],self.ORIGINAL_NIC_INFO['IP'])}] {self.CHANGED_NIC_info['IP']:<30}"
        )
        print(
            f"[{Fore.GREEN}ORIGINAL{Fore.RESET}] {self.ORIGINAL_NIC_INFO['interface']:<20}{'    ======>':<20}"
            f"[{self.get_status(self.CHANGED_NIC_info['interface'],self.ORIGINAL_NIC_INFO['interface'])}] {self.CHANGED_NIC_info['interface']:<30}"
        )
        print(
            f"[{Fore.GREEN}ORIGINAL{Fore.RESET}] {self.ORIGINAL_NIC_INFO['netmask']:<20}{'    ======>':<20}"
            f"[{self.get_status(self.CHANGED_NIC_info['netmask'],self.ORIGINAL_NIC_INFO['netmask'])}] {self.CHANGED_NIC_info['netmask']:<30}"
        )
    # Functionality not available yet for Windows (It's to much work and i need to change registry and reset it etc)
    def change_windows_mac(self):
        print(f"[{Fore.BLUE}INFO{Fore.RESET}] Functionality not available for Windows yet") # Give info if the OS is windows
    # Change MAC of Linux
    def change_Linux_mac(self):
        subprocess.call(["sudo", "ifconfig", self.ORIGINAL_NIC_INFO["interface"], "down"]) # Closing the NIC to change MAC
        subprocess.call(["sudo", "ifconfig", self.ORIGINAL_NIC_INFO["interface"], "hw", "ether", self.CHANGE_MAC_TO]) # Change the MAC of the NIC
        subprocess.call(["sudo", "ifconfig", self.ORIGINAL_NIC_INFO["interface"], "up"]) # Start the NIC
    def generate_random_mac(self) -> str:
        mac = [0x02, random.randint(0x00, 0x7f)] + [random.randint(0x00, 0xff) for _ in range(4)] # Generate an 6 in length with 12 hex characters
        return ':'.join(f"{byte:02x}" for byte in mac) # Joins the hex valus and returns the generated MAC 
    def get_status(self,data1,data2) -> str:
        return f"{Fore.GREEN}UNCHANGED{Fore.RESET}" if  data1 == data2 else  f"{Fore.BLUE}CHANGED{Fore.RESET}" # Checks if the values of the 2 given variables differ and returns if it's changed or not
