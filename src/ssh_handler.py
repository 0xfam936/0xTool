import paramiko
from colorama import Fore, init
class ssh_client:
    def __init__(self, host: str, port: int = 22, username: str = None, password: str = None, key_path: str = None):
        self.HOST = host
        self.PORT = port
        self.USERNAME = username
        self.PASSWORD = password
        self.KEY_PATH = key_path
    def start(self):
        CONNECTION = self.connect() # Try to make an SSH connection to the given parameters
        if CONNECTION is not None: # Check if the connection is successfull
            self.interactive_shell(CONNECTION)  # Pass the client to interactive_shell
    def connect(self) -> "paramiko.client.SSHClient": # Return value type paramiko.client.SSHClient
        init(autoreset=True) # Reset text color after every print
        try:
            print(f"{Fore.CYAN}Connecting to {self.HOST}:{self.PORT}") # Info about trying to connect with the given parameters
            CLIENT = paramiko.SSHClient() # Paramiko initialises SSH client class
            CLIENT.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # Handles unknown host keys (just accept and add the key)
            if self.KEY_PATH:
                try: 
                    with open(self.KEY_PATH, "r") as key_file:
                        KEY = paramiko.RSAKey.from_private_key(key_file) # If key path given gives PKey object using the private key file for connecting
                    CLIENT.connect(hostname=self.HOST, port=self.PORT, username=self.USERNAME, pkey=KEY) # Try connecting using Key object
                except:
                    print(f"[{Fore.RED}ERROR{Fore.RESET}] Authentication failed for {self.USERNAME}@{self.HOST} invalid RSA file") # Give the correct error if the RSA key is not correct
            else:
                CLIENT.connect(hostname=self.HOST, port=self.PORT, username=self.USERNAME, password=self.PASSWORD) # Try connecting using password if key is not given                
            print(f"[{Fore.GREEN}+{Fore.RESET}] Connected to {self.USERNAME}@{self.HOST}:{self.PORT}") # Show if connection is successful
            return CLIENT # Returns client object if connection successful
        except paramiko.AuthenticationException: # Handles authentication error
            print(f"[{Fore.RED}ERROR{Fore.RESET}] Authentication failed for {self.USERNAME}@{self.HOST}")
        except paramiko.SSHException as e: # Handles ssh exception
            print(f"[{Fore.RED}ERROR{Fore.RESET}] SSH error: {str(e)}")
        except Exception as e: # Handles the all other exceptions
            print(f"[{Fore.RED}ERROR{Fore.RESET}] Unexpected error: {str(e)}")        
        # If connection failed, return None
        return None
    def interactive_shell(self, client: "paramiko.client.SSHClient"):
        print(f"[{Fore.GREEN}*{Fore.RESET}] Starting interactive shell. Type 'quit' or 'exit' to close connection.") # Info about the interactive ssh shell
        while True: # Loop until given command is quit or exit
            try:
                command = input(f"{self.HOST}@{self.USERNAME}$ ") # Wait for an command input
                if command.lower() in ["exit", "quit"]: # checks if the command is to quit
                    print(f"[{Fore.RED}Exiting{Fore.RESET}] Closing connection to {self.HOST}:{self.PORT}") # Info about closing
                    client.close()  # Close the SSH connection
                    break # Braks the loop
                else: 
                    stdin, stdout, stderr = client.exec_command(command)  # Execute the command
                    print(stdout.read().decode(), end="") # Decode and show the output 
                    error = stderr.read().decode() # Decode error
                    if error:
                        print(error, end="") # If error exist show the error
            except Exception as e:
                print(f"[{Fore.RED}ERROR{Fore.RESET}] Invalid input: {str(e)}") # Show error if invalid input given
