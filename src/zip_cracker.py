import zipfile
import itertools
import zlib
import string
import helper_functions
from time import sleep
from colorama import Fore, init
from pathlib import Path
from tqdm import tqdm
init(autoreset=True)
class ZipCrack:
    def __init__(self, file: str, wordlist: str = None, brute_min_char: int = None, brute_max_char: int = None):
        self.TARGET = Path(file)
        self.WORDLIST = Path(wordlist) if wordlist else None
        self.MIN_BRUTEFORCE_CHAR = brute_min_char
        self.MAX_BRUTEFORCE_CHAR = brute_max_char
    def return_files_data(self):
        # Check if ZIP file exists
        if not self.TARGET.is_file():
            print(f"[{Fore.RED}ERROR{Fore.RESET}] Zip file not found at {self.TARGET}.")
            sleep(2)
            raise helper_functions.exit_program()  # Gracefully exit if file is not found
        wordlist_data = None
        if self.WORDLIST:
            try:
                with self.WORDLIST.open("rb") as wordlist_file:
                    wordlist_data = wordlist_file.read().splitlines()
                return wordlist_data
            except Exception as e:
                print(f"[{Fore.RED}ERROR{Fore.RESET}] Error reading wordlist file: {e}. Proceeding with brute-force...")
                return None
        else:
            print(f"[{Fore.BLUE}INFO{Fore.RESET}] No wordlist provided. Starting brute-force...")
            return None
    def brute_force_generator(self, min_length, max_length, charset=None):
        print(f"[{Fore.BLUE}INFO{Fore.RESET}] Generating brute force data between {min_length}-{max_length} characters")
        if charset is None:
            charset = string.ascii_lowercase + string.digits
        for length in range(min_length, max_length + 1):
            for item in itertools.product(charset, repeat=length):
                yield ''.join(item).encode()
    def start(self):
        try:
            wordlist = self.return_files_data()
            # Ensure only one mode runs at a time
            if wordlist is None:
                # Brute-force mode
                charset = string.ascii_lowercase + string.digits
                total_guesses = sum(len(charset) ** i for i in range(self.MIN_BRUTEFORCE_CHAR, self.MAX_BRUTEFORCE_CHAR + 1))
                generator = self.brute_force_generator(self.MIN_BRUTEFORCE_CHAR, self.MAX_BRUTEFORCE_CHAR, charset)
                with zipfile.ZipFile(self.TARGET) as zip_file:  # Initialize zipfile class to crack
                    for password in tqdm(generator, total=total_guesses, desc="Brute-forcing", unit="attempt"):
                        try:
                            zip_file.extractall(pwd=password)
                        except (RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile, ValueError, zlib.error):
                            continue
                        else:
                            print(f"\n[{Fore.GREEN}SUCCESS{Fore.RESET}] ZIP FILE CRACKED!")
                            print(f"[{Fore.GREEN}+{Fore.RESET}] PASSWORD: {password.decode(errors='ignore')}")
                            return  # Exit after success, don't proceed further
                    print(f"\n[{Fore.RED}FAILED{Fore.RESET}] Password not found.")
            else:
                # Wordlist mode
                with zipfile.ZipFile(self.TARGET) as zip_file:
                    for password in tqdm(wordlist, total=len(wordlist), desc="Cracking", unit="word"):
                        if isinstance(password, str):
                            password = password.encode('utf-8')
                        try:
                            zip_file.extractall(pwd=password.strip())  # Try password
                        except (RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile, ValueError, zlib.error):
                            continue
                        else:
                            # Give info if cracked
                            print(f"\n[{Fore.GREEN}SUCCESS{Fore.RESET}] ZIP FILE CRACKED!")
                            print(f"[{Fore.GREEN}+{Fore.RESET}] PASSWORD: {password.decode(errors='ignore').strip()}")
                            return  # Exit after success, don't proceed further
                    # Give info if failed
                    print(f"\n[{Fore.RED}FAILED{Fore.RESET}] Password not found in wordlist.")
        except Exception as e:
            print(f"[{Fore.RED}ERROR{Fore.RESET}] Unexpected error: {e}")
            raise helper_functions.exit_program()
if __name__ == "__main__":
    # Use relative paths (e.g. place your ZIP in a folder named "zips")
    zip_file = r"C:\Users\Muham\Downloads\Spookifier.zip"
    wordlist_file = r"C:\Users\Muham\Downloads\Tools\wordlist\pwlist.txt"  # Or something like "wordlists/common.txt"
    # Ensure that you're only calling the start() method once:
    crack = ZipCrack(
        file=zip_file,
        wordlist=wordlist_file,  # Comment out this line to run brute-force only
        brute_min_char=1,
        brute_max_char=3  # You can increase this for stronger attempts
    )
    crack.start()
