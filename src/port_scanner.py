import socket
import time
from tqdm import tqdm
from colorama import Fore
class portscanner:
    def __init__(self, IP: str, begin_port: int, end_port: int, speed: float = 1):
        self.IP = IP
        self.BEGIN_PORT = begin_port
        self.END_PORT = end_port
        self.SPEED = speed
        self.NAME = self.get_host_name(self.IP)  # Get hostname using IP
    def scan(self):
        print(f"\n[{Fore.BLUE}INFO{Fore.RESET}] Scanning {self.BEGIN_PORT}-{self.END_PORT} ports on {self.IP} ({self.NAME})...\n") # Show info of scanning parameters 
        START_TIME = time.time() # Start of the scanning
        for port in tqdm(range(self.BEGIN_PORT, self.END_PORT), desc="Scanning", unit="port"): # Progress bar and the port range to loop for
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Socket for scanning
            sock.settimeout(self.SPEED) # Setting an timeout time for the packet 
            result = sock.connect_ex((self.IP, port)) # Tries to connect to the give socket
            sock.close() # Closes the socket after done
            if result == 0: # If succesful 
                service = self.get_port_service_by_port(port) # Get service for the port
                tqdm.write(f"[{Fore.GREEN}OPEN{Fore.RESET}] Port {port:<5} → {service}") # Show the result in an formatted way
                tqdm.write("-"*40) # Underscores for beter visual presentation
        tqdm.write(f"[{Fore.BLUE}INFO{Fore.RESET}] Enter to return to main menu") # Info on what to do to return to menu
        input() # Wait on enter to return to main menu
    def get_port_service_by_port(self, port, protocol="tcp"):
        try:
            return socket.getservbyport(port, protocol) # Tries to return service using posrt and protocol
        except:
            return "UNKNOWN" # If cannot return UNKNOWN is passed
    def get_host_name(self, IP: str) -> str:
        try:
            return socket.gethostbyaddr(IP)[0] # Tries to get hostname using IP
        except:
            return "UNKNOWN" # If cannot return UNKNOWN is passed
