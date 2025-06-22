import asyncio
import aiohttp
import re
from tqdm import tqdm
from colorama import Fore
from helper_functions import console_handler, exit_program
from bs4 import BeautifulSoup as soup
from urllib.parse import urljoin, urlparse, urlunparse
class asynchronous_webScraper:
    def __init__(self, start_url: str, link: bool = True, contact: bool = True, threads: int = 150, timeout: int = 10):
        self.start_url = self.normalize_url(start_url)
        self.FIND_LINK = link
        self.FIND_CONTACT = contact
        self.TIMEOUT = timeout
        self.SOCIAL_DOMAINS = ['facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com']
        self.visited_urls = set()
        self.queued_urls = set()
        self.contact_info = {}
        self.url_queue = asyncio.Queue()
        self.url_queue.put_nowait(self.start_url)
        self.queued_urls.add(self.start_url)
        self.THREADS = threads
        self.RATE_LIMITER = asyncio.Semaphore(5)
        self.email_regex = re.compile(r"^\S+@\S+\.\S+$")
        self.phone_regex = re.compile(r'^\+?[1-9][0-9]{7,14}$')
    def normalize_url(self, url):
        parsed = urlparse(url)
        cleaned = parsed._replace(fragment='', query='')
        return urlunparse(cleaned).rstrip('/')
    async def fetch(self, session, url):
        try:
            async with self.RATE_LIMITER:
                async with session.get(url, timeout=self.TIMEOUT) as response:
                    if response.status == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                        return await response.text()
        except Exception as e:
            print(f"[{Fore.RED}ERROR{Fore.RESET}] Failed to get response from {url}: {e}")
        return None
    async def process_url(self, session, progress_bar):
        try:
            while True:
                url = await self.url_queue.get()
                if url in self.visited_urls:
                    self.url_queue.task_done()
                    continue
                print(f"\n[{Fore.GREEN}PROCESSING{Fore.RESET}]: {url}")
                self.visited_urls.add(url)
                self.contact_info[url] = {
                    "emails": set(),
                    "phones": set(),
                    "social_media": set()
                }

                html = await self.fetch(session, url)
                if not isinstance(html, str):  # Fix: Only parse if it's a valid string
                    self.url_queue.task_done()
                    continue
                content = soup(html, 'html.parser')
                if self.FIND_CONTACT:
                    self.extract_contacts(url, content)
                if self.FIND_LINK:
                    self.extract_links(url, content)
                progress_bar.update(1)
                self.url_queue.task_done()
        except asyncio.CancelledError:
            return
    def extract_contacts(self, url, content):
        text = content.get_text()
        emails = self.email_regex.findall(text)
        phones = self.phone_regex.findall(text)
        links = [a['href'] for a in content.find_all('a', href=True)]
        social_links = [link for link in links if any(domain in urlparse(link).netloc for domain in self.SOCIAL_DOMAINS)]
        self.contact_info[url]["emails"].update(emails)
        self.contact_info[url]["phones"].update(phones)
        self.contact_info[url]["social_media"].update(social_links)
    def extract_links(self, base_url, content):
        links = [urljoin(base_url, a['href']) for a in content.find_all('a', href=True)]
        for link in links:
            normalized = self.normalize_url(link)
            if normalized.startswith('#'):
                continue
            if any(domain in urlparse(normalized).netloc for domain in self.SOCIAL_DOMAINS):
                continue
            if normalized not in self.visited_urls and normalized not in self.queued_urls:
                self.url_queue.put_nowait(normalized)
                self.queued_urls.add(normalized)
    async def run(self):
        connector = aiohttp.TCPConnector(limit=self.THREADS, ttl_dns_cache=300)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0',
            'Accept-Encoding': 'gzip, deflate'
        }
        async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
            with tqdm(total=1, desc="Scraping", unit="URL") as progress_bar:
                tasks = [asyncio.create_task(self.process_url(session, progress_bar)) for _ in range(self.THREADS)]
                previous_total = -1
                stable_count = 0
                while True:
                    current_total = len(self.visited_urls) + self.url_queue.qsize()
                    if current_total != previous_total:
                        progress_bar.total = current_total
                        progress_bar.refresh()
                        previous_total = current_total
                        stable_count = 0
                    else:
                        stable_count += 1
                    if stable_count >= 20:
                        break
                    await asyncio.sleep(0.5)
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        self.print_results()
    def start(self):
        try:
            asyncio.run(self.run())
        except KeyboardInterrupt:
            print(f"\n[{Fore.RED}EXITING{Fore.RESET}] Keyboard interrupt received. Shutting down.")
            raise exit_program()
    def print_results(self):
        console = console_handler()
        console.clear()
        console.banner("WEB SCRAPPER")
        print("\n--- Scraping Complete ---\n")
        total_emails = set()
        total_phones = set()
        total_socials = set()
        for url, data in self.contact_info.items():
            total_emails.update(data["emails"])
            total_phones.update(data["phones"])
            total_socials.update(data["social_media"])
        print(f"[{Fore.BLUE}INFO{Fore.RESET}] VISITED URL COUNT: {len(self.visited_urls)}")
        print(f"[{Fore.BLUE}INFO{Fore.RESET}] TOTAL EMAILS FOUND: {len(total_emails)}")
        print(f"[{Fore.BLUE}INFO{Fore.RESET}] TOTAL PHONE NUMBERS FOUND: {len(total_phones)}")
        print(f"[{Fore.BLUE}INFO{Fore.RESET}] TOTAL SOCIAL LINKS FOUND: {len(total_socials)}")
        for url in sorted(self.contact_info):
            print(f"{Fore.BLUE}WEBSITE{Fore.RESET}: {url}")
            data = self.contact_info[url]
            if data["phones"]:
                for phone in sorted(data["phones"]):
                    print(f"  {Fore.GREEN}PHONE{Fore.RESET}: {phone}")
            if data["emails"]:
                for email in sorted(data["emails"]):
                    print(f"  {Fore.YELLOW}EMAIL{Fore.RESET}: {email}")
            if data["social_media"]:
                for social in sorted(data["social_media"]):
                    print(f"  {Fore.MAGENTA}SOCIAL{Fore.RESET}: {social}")
            print("-" * 100)
        input("Press enter to go back to main menu.\n")
        raise exit_program()
