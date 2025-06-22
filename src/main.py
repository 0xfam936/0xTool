import pyfiglet
import helper_functions 
import MAC_spoofing
import ssh_handler
import pathlib
import dos
import mitm
import zip_cracker
from port_scanner import portscanner
from time import sleep
from getpass import getpass
from colorama import Fore, Style, init
from network_scanner import netscan
from socket import herror
from webscraper import asynchronous_webScraper
init(autoreset=True) # Color auto reset after printing the banner 
menu=[
    {"ID":1,"Description":"Network scanner (ARP)"},
    {"ID":2,"Description":"Portscanner (TCP)"},
    {"ID":3,"Description":"MAC changer (Not working for Windows yet)"},
    {"ID":4,"Description":"SSH client"},
    {"ID":5,"Description":"DOS"},
    {"ID":6,"Description":"MITM attack"},
    {"ID":7,"Description":"Webscraper"},
    {"ID":8,"Description":"Zip cracker"}
] # Menu array
def main_banner() -> str:
    ascii_banner = pyfiglet.figlet_format("0xTool") # Formats the string to Ascii art
    version = "Version 1.1\n".center(60) # Shows version
    subtitle = "Made by 0xfam936\n\n".center(20)  # Adjust the position horizontally and places the subtitle
    return Fore.RED + Style.BRIGHT + ascii_banner + version + Style.DIM + subtitle # Returns the adjusted string
def show_menu(menu):
    for item in menu:
        print(f"{item["ID"]}) {item["Description"]}") # Show all menu items in list 
    print(f"{len(menu) + 1}) Exit")
if __name__ == "__main__":
    repeat = True
    helper_functions.exit_handler().start() # Start exit handler for user interruption
    console = helper_functions.console_handler() # Console handler
    while repeat:
        try:
            console.clear() # Clears screen
            print(main_banner())
            show_menu(menu) # Shows main menu
            while True: # Loop until break
                try:
                    option = int(input("$ ")) - 1 # Get the chosen option if possible needs to be a number and do minus 1 as the new option
                    if option < len(menu): # Check if option is lesser than the length of the menu
                        break # Break loop if option is lesser than the length of the menu
                    elif option == len(menu):
                        print(f"[{Fore.RED}!{Fore.RESET}] User input received quiting...")
                        sleep(3)
                        raise helper_functions.exit_program()
                    else:
                        print(f"[{Fore.RED}Error{Fore.RESET}] Please choose a valid option.") # Show Error if a higher number
                except ValueError:
                        print(f"[{Fore.RED}Error{Fore.RESET}] Please enter a valid number.") # Show Error if a not a number
                        raise helper_functions.return_to_menu()
            console.clear() # Clear console after an valid option 
            if option == 0:
                cidr = helper_functions.device_info().get_NIC_info(helper_functions.device_info().get_IP())["cidr"] # Get NIC info of the internet connected mainly used NIC
                timeout_range = [1,10] # Default timeout ranges
                MAC = "ff:ff:ff:ff:ff:ff" # Default broadcast MAC
                user_input = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] IP in prefix format default => {cidr}> ") # Get user input for CIDR
                if helper_functions.validate_network_info().is_valid_cidr(user_input):
                    cidr = user_input # Change default cidr if valid cidr given
                else:
                    print(f"[{Fore.GREEN}INFO{Fore.RESET}] No new CIDR provided, using default: {cidr}") # Give info if the default cidr isn't changed
                
                user_input = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] MAC address => {MAC}> ") # Get user input for MAC

                if helper_functions.validate_network_info().is_valid_MAC(user_input):
                    MAC = user_input # Change default MAC if valid MAC given
                else:
                    print(f"[{Fore.GREEN}INFO{Fore.RESET}] No new Mac provided, using default: {MAC}")  # Give info if the default MAC isn't changed

                try: # Ask user for an timeout range for the ARP requests and if not given an correct value throw exception
                    user_input = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Timeout range default => {timeout_range[0]}-{timeout_range[1]}> ").replace(" ","")
                    user_input = user_input.split("-")
                    timeout_range[0] = int(user_input[0])
                    timeout_range[1] = int(user_input[1])
                except:
                    print(f"[{Fore.GREEN}INFO{Fore.RESET}] No correct range provided, using : {timeout_range[0]}-{timeout_range[1]}") # Give info if the default range isn't changed
                console.clear() # Clear console
                console.banner("NETWORK SCANNER",40) # Show a new banner with "NETWORK SCANNER" as title with 40 characters long banner
                IP = cidr.split("/")[0] # Get IP using cidr
                nic_info = helper_functions.device_info().get_NIC_info(IP) # Get NIC info
                # Show the used parameters for the scanner
                print(f"\n[{Fore.BLUE}INFO{Fore.RESET}] interface=>{nic_info["interface"]}")
                print(f"[{Fore.BLUE}INFO{Fore.RESET}] IP=>{IP}")
                print(f"[{Fore.BLUE}INFO{Fore.RESET}] netmask=>{nic_info["netmask"]}")
                print(f"[{Fore.BLUE}INFO{Fore.RESET}] MAC=>{MAC}")
                print(f"[{Fore.BLUE}INFO{Fore.RESET}] timeout speed(s)=>{timeout_range[0]}-{timeout_range[1]}\n")
                network_scanner = netscan(cidr,MAC,timeout_range[0],timeout_range[1]) # Initialise scanner with the parameters 
                network_scanner.start() # Start the scanner
            if option == 1:
                port_range=[1,500]
                speed = 1
                while True:
                    IP = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] IP > ") # Get user input for target IP
                    if helper_functions.validate_network_info().is_valid_IP(IP):
                        break # If valid IP break the loop
                    else:
                        print(f"[{Fore.RED}ERROR{Fore.RESET}] No valid IP given") # Give error if no valid IP given.
                while True: 
                    try:
                        user_input = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Port range default => {port_range[0]}-{port_range[1]}> ") # Get user input for the port range
                        # Try to parse input for range 
                        user_input = user_input.split("-")
                        port_range[0] = int(user_input[0])
                        port_range[1] = int(user_input[1])
                        if port_range[0] < port_range[1]:
                            break # exit loop if input is correct
                        else:
                            print(f"[{Fore.RED}ERROR{Fore.RESET}] Invalid range") # Give error for invalid range if the numbers > 0 or end < begin 
                    except: 
                            break # Break loop if invalid input                      
                            print(f"[{Fore.GREEN}INFO{Fore.RESET}] No correct range provided, using : {port_range[0]}-{port_range[1]}") # Give info if the default range isn't changed
                try:
                    user_input = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Speed per port default => {speed}> ") # Get user input for the speed
                    # Try to parse input for speed and save
                    user_input = int(user_input) 
                    speed = user_input
                except:
                    print(f"[{Fore.GREEN}INFO{Fore.RESET}] No correct speed provided, using : {speed}s") # Give info if the default speed isn't changed
                console.clear()
                console.banner("PORT SCANNER",40) # Show a new banner with "PORT SCANNER" as title with 40 characters long banner
        
                portscanner(IP,port_range[0],port_range[1],speed).scan() # Start the port scanner   
            if option == 2:
                mac = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Give a valid mac to change to  default => random> ") # Get user input for the port range
                if helper_functions.validate_network_info().is_valid_MAC(mac): # Check if the given MAC is valid
                    MAC_spoofing.MAC_spoof(mac).change_mac() # Change MAC if the given MAC is valid 
                else:
                    print(f"[{Fore.BLUE}INFO{Fore.RESET}] No valid MAC provided using an random MAC\n") # Give info if the given MAC isn't valid
                    MAC_spoofing.MAC_spoof().change_mac() # Change MAC to an random MAC if the given MAC is not valid
                    input("Enter to return to main menu")
            if option == 3:
                while True:
                    HOST = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] HOST> ") # Get user input for hostname or IP
                    if len(HOST) >= 1: # Check if the length of the input is bigger or equal to 1 
                        break # Break if condition is true
                while True:
                    USERNAME = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] username> ").strip() # Get user input for username and strip of any white spaces
                    if len(USERNAME) >= 1: # Check if the length of the input is bigger or equal to 1
                        break # Break if condition is true            
                # Get user input for port and not a valid number given returns 22
                try: 
                    PORT = int(input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] PORT default => 22> ").strip()) 
                except: 
                    PORT = 22
                PASSWORD = getpass(f"[{Fore.YELLOW}INPUT{Fore.RESET}] PASSWORD> ") # Get user input for password
                PASSWORD = PASSWORD if PASSWORD else None # Check user input if empty return None
                KEY_PATH = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] KEY FILE PATH (for passwordless login)> ") # Get user input for key path
                KEY_PATH =  pathlib.Path(KEY_PATH) if KEY_PATH.strip() else None # Check user input if empty return None else returns correct system path
                ssh_handler.ssh_client(HOST,PORT,USERNAME,PASSWORD,KEY_PATH).start() # Start the SSH client
            if option == 4:
                methods = ["GET", "POST", "TCP"] # Method list
                console.banner("METHOD") # Custom banner
                for index, method in enumerate(methods, start=1):
                    print(f"{index}) {method}") # Shows the methods

                # Gets input for method control if its correct if false ask again till you get a correct 1
                while True:
                    user_input = input(f"\n[{Fore.YELLOW}INPUT{Fore.RESET}] METHOD> ") 
                    if user_input.isdigit() and 1 <= int(user_input) <= len(methods):
                        METHOD = methods[int(user_input) - 1]
                        break
                    else:
                        print(f"[{Fore.RED}ERROR{Fore.RESET}] Invalid method")
                # Check if the methods are get of post for customised asking for parameters
                if METHOD in ["GET", "POST"]:
                    # Gets input for target control if its correct if false ask again till you get a correct 1
                    while True:
                        TARGET = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Target (http(s)://example.com)> ") 
                        if len(TARGET) > 11 and (TARGET.startswith("http://") or TARGET.startswith("https://")):
                            break
                        else:
                            print(f"[{Fore.RED}ERROR{Fore.RESET}] Invalid TARGET format")
                    # Get input for changing auto changing user agent
                    get_changing_agent_auto = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Get random user agent every request (y/n) default => y> ").lower() != "n"
                    # Get input for 1 time random user agent if none asked return none
                    get_user_agent = True if get_changing_agent_auto else input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Get random user agent 1 time (y/n) default => y> ").lower() != "n"
                    # Get input for custom header if user wants 1 time random user agent if he/ she doesn't want random user agent every request
                    custom_header = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Do you want a custom header default => n> ").lower() == "y"
                    # Get input if user wants a custom payload to send in HTTP request
                    payload = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Do you want to send custom default => n> ").lower() == "y"
                    if payload:
                        custom_header = True
                else:
                    while True:
                        # Asks user for target and checcks the format
                        TARGET = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Target> ")
                        if len(TARGET) > 4 and not (TARGET.startswith("http://") or TARGET.startswith("https://")):
                            break
                        else:
                            print(f"[{Fore.RED}ERROR{Fore.RESET}] Invalid TARGET format")
                # Asks for a packet count to send 
                PACKET_COUNT = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] How many packets Enter/0 => unlimited> ")
                PACKET_COUNT = int(PACKET_COUNT) if PACKET_COUNT.isdigit() and int(PACKET_COUNT) > 0 else 0
                # Asks for a wait time between requests
                WAIT = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] How many seconds between requests (s) default => 0s> ")
                WAIT = int(WAIT) if WAIT.isdigit() and int(WAIT) > 0 else 0
                # Checks and choses the correct data to send for the DOS operation to start
                try:
                    if METHOD == "TCP":
                        DOS = dos.dos(TARGET, WAIT, METHOD, PACKET_COUNT)
                    else:
                        DOS = dos.dos(TARGET, WAIT, METHOD, PACKET_COUNT, get_user_agent, custom_header, get_changing_agent_auto, payload)
                    DOS.start() # Start the dos attack
                except KeyboardInterrupt:
                    raise helper_functions.return_to_menu() # Return to main menu if interruption received
            if option == 5:
                """
                Needed options for man in the middle
                """
                PACKET_FORWARDING = True
                TARGET1 = None
                TARGET2 = None
                WAIT = 1
                console.clear()
                console.banner("MITM")
                """
                Asks user fir the needed parameters, first/second target, wait time between arp requests
                and if the user wants to port forward. If port forward is false the 2 device couldnt send packets to each other because it will stop with you 
                """
                while True:
                    user_input = user_input = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Target1> ")
                    if helper_functions.validate_network_info().is_valid_IP(user_input):
                        TARGET1 = user_input
                        break
                    else:
                        print(f"[{Fore.RED}ERROR{Fore.RESET}] Invalid target ")
                while True:
                    user_input = user_input = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Target2> ")
                    if helper_functions.validate_network_info().is_valid_IP(user_input):
                        TARGET2 = user_input
                        break
                    else:
                        print(f"[{Fore.RED}ERROR{Fore.RESET}] Invalid target ")     

                user_input = user_input = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Would you like to do packet forwarding (y/n) (need admin) default => y> ")
                if user_input == "n":
                    PACKET_FORWARDING = False
                
                user_input = user_input = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] How many time (s) between ARP request default => 1> ")
                if user_input.isdigit():
                    WAIT = int(user_input)
                """
                Formatted info of the given parameters
                """
                console.clear()
                console.banner("MITM")
                print(f"[{Fore.BLUE}INFO{Fore.RESET}] TARGET 1: {TARGET1}")     
                print(f"[{Fore.BLUE}INFO{Fore.RESET}] TARGET 2: {TARGET2}")
                print(f"[{Fore.BLUE}INFO{Fore.RESET}] FORWARDING Enabled: {PACKET_FORWARDING}\n")          
                print(f"[{Fore.BLUE}INFO{Fore.RESET}] WAIT TIME BETWEEN ARP REQUESTS: {WAIT}")
                mitm.MITM(TARGET1,TARGET2,PACKET_FORWARDING,WAIT).spoof() # Start the man in the middle attack
            if option == 6:
                """
                Get user input for the webscrapper
            
                """
                while True:
                    target = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Target to scrape (example:http(s)://example.com)> ")
                    if len(target) > 4 and (target.startswith("http://") or target.startswith("https://")):
                            break
                    else:
                        continue
                user_input = user_input = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Would you like to search and proccess links (y/n) default => y> ")
                if user_input == "n":
                    link = False
                else:
                    link = True
                user_input = user_input = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Would you like to search contact information (y/n) default => y> ")
                if user_input == "n":
                    contact_info = False
                else:
                    contact_info = True
                user_input = user_input = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] How many threads would you like to use default => 100> ")
                try:
                    threads = int(user_input)
                except:
                    threads = 100
                user_input = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Request timeout (s) default => 10> ")
                try:
                    timeout = int(user_input)
                except:
                    timeout = 10
                webscraper = asynchronous_webScraper(target,link,contact_info,threads,timeout) # Initialise the webscrapper with the given input parameters
                webscraper.start() # Start webscrapper
            if option == 7:
                max_length = None
                min_length = None
                wordlist = None
                # Get the target zip file path
                while True:
                    user_input = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Target zip file> ")
                    if user_input.endswith(".zip"):
                        try:
                            with open(user_input, "r"):
                                target_file = user_input
                                break
                        except IOError: # If invalid path
                            print(f"[{Fore.RED}ERROR{Fore.RESET}] Invalid path.")
                    else:
                        print(f"[{Fore.RED}ERROR{Fore.RESET}] Invalid zip file.")
                # Ask for the attack type: brute force or list attack
                user_input = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Brute force or list attack (b/l), default => b> ")
                if user_input == "l":
                    # List attack: Get the wordlist file path
                    while True:
                        user_input = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Wordlist file> ")
                        try:
                            with open(user_input, "r"):
                                wordlist = user_input
                                break
                        except IOError:
                            print(f"[{Fore.RED}ERROR{Fore.RESET}] Invalid wordlist path.")
                else:
                    # Brute force attack: Get the min and max password length
                    while True:
                        user_input = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Bruteforce min password length> ")
                        try:
                            min_length = int(user_input)
                            break
                        except ValueError:
                            print(f"[{Fore.RED}ERROR{Fore.RESET}] Invalid min password length.")
                    
                    while True:
                        user_input = input(f"[{Fore.YELLOW}INPUT{Fore.RESET}] Bruteforce max password length> ")
                        try:
                            max_length = int(user_input)
                            break
                        except ValueError:
                            print(f"[{Fore.RED}ERROR{Fore.RESET}] Invalid max password length.")

                # Start the zip cracker process
                crack = zip_cracker.ZipCrack(target_file, wordlist, min_length, max_length)
                crack.start()
                input(f"{Fore.CYAN}Enter to return to main menu.")
        except helper_functions.exit_program: # Exception to exit the program
            break
        except helper_functions.return_to_menu: # Exception to return to menu
            continue
        except herror: # Handles network error
            print(f"\n[{Fore.RED}ERROR{Fore.RESET}] Network error. Returning to main menu...")
            sleep(3)
            continue
