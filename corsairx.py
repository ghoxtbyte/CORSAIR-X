#!/usr/bin/env python3
import sys
import asyncio
import aiohttp
import argparse
import re
import itertools
from urllib.parse import urlparse, urljoin, urlunparse
from colorama import Fore, Style, init
from bs4 import BeautifulSoup
import aiofiles
from tqdm.asyncio import tqdm

# Initialize Colorama
init(autoreset=True)

# --- Configuration & Constants ---
DEFAULT_TIMEOUT = 10
DEFAULT_CONCURRENCY = 20
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# Global Sets for Deduplication and Skip Logic
VULNERABLE_DOMAINS = set()
SCANNED_URLS = set()
CRAWLED_URLS = set()
# Set to store signatures of reported vulns to prevent duplicates across http/https
REPORTED_SIGNATURES = set()

# --- Utility Functions ---

def print_banner():

    banner = rf"""
{Fore.RED}   ______ ____  ____  _____ ___    ____  ____       _  __
  / ____// __ \/ __ \/ ___//   |  /  _/ / __ \     | |/ /
 / /    / / / / /_/ /\__ \/ /| |  / /  / /_/ /____ |   / 
/ /___ / /_/ / _, _/___/ / ___ |_/ /  / _, _/_____/   |  
\____/ \____/_/ |_|/____/_/  |_/___/ /_/ |_|     /_/|_|  
                                                         
{Fore.CYAN}    =====================================================
      CORSAIR-X | Advanced CORS Misconfiguration Scanner
    ====================================================={Style.RESET_ALL}
    """
    print(banner)

def get_domain_from_url(url):
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except:
        return None

def normalize_url(url):
    """Removes parameters, keeps only the endpoint path."""
    try:
        parsed = urlparse(url)
        # Reconstruct without params, query, fragment
        clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
        if clean_url.endswith('/') and len(clean_url) > 10: 
            clean_url = clean_url[:-1]
        return clean_url
    except:
        return url

# --- Core Logic Classes ---

class CORSScanner:
    def __init__(self, args):
        self.args = args
        self.timeout = aiohttp.ClientTimeout(total=args.timeout)
        self.semaphore = asyncio.Semaphore(args.concurrency)
        self.headers = {'User-Agent': USER_AGENT}
        
        # Parse custom headers
        if args.custom_header:
            for header_input in args.custom_header:
                # Split by semicolon to allow multiple headers in one string
                # Example: "cookie: test=1234; user-agent:Linux"
                split_headers = header_input.split(";")
                for h in split_headers:
                    if ":" in h:
                        k, v = h.split(":", 1)
                        self.headers[k.strip()] = v.strip()
            
            if self.args.debug:
                tqdm.write(f"{Fore.BLUE}[DEBUG] Custom Headers Loaded: {self.headers}")

        # Load custom origins if any
        self.custom_origins = []
        if args.origins:
            try:
                with open(args.origins, 'r') as f:
                    self.custom_origins = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                self.custom_origins = [args.origins.strip()]
            except Exception:
                self.custom_origins = [args.origins.strip()]
            
            if self.args.debug:
                tqdm.write(f"{Fore.BLUE}[DEBUG] Custom Origins Loaded: {len(self.custom_origins)}")

        # Proxy Configuration
        self.proxies = []
        if args.proxy:
            self.proxies.append(args.proxy)
        
        if args.proxy_file:
            try:
                with open(args.proxy_file, 'r') as f:
                    file_proxies = [line.strip() for line in f if line.strip()]
                    self.proxies.extend(file_proxies)
                if self.args.debug:
                    tqdm.write(f"{Fore.BLUE}[DEBUG] Loaded {len(file_proxies)} proxies from file.")
            except Exception as e:
                print(f"{Fore.RED}[!] Error reading proxy file: {e}")
        
        # Cycle iterator for round-robin proxy usage
        self.proxy_pool = itertools.cycle(self.proxies) if self.proxies else None

    def get_next_proxy(self):
        """Returns the next proxy from the pool or None if no proxies are set."""
        if self.proxy_pool:
            p = next(self.proxy_pool)
            return p
        return None

    async def get_smart_protocols(self, raw_url):
        """
        Determines if http, https or both are available.
        Handles urls without scheme.
        """
        raw_url = raw_url.strip()
        parsed = urlparse(raw_url)
        
        if self.args.debug:
            tqdm.write(f"{Fore.BLUE}[DEBUG] resolving protocol for: {raw_url}")

        targets = []
        schemes_to_try = []

        if not parsed.scheme:
            schemes_to_try = ['https', 'http']
            base_url = raw_url
        else:
            if parsed.scheme == 'http':
                schemes_to_try = ['http', 'https']
            else:
                schemes_to_try = ['https', 'http']
            base_url = parsed.netloc + parsed.path

        valid_urls = []
        
        async with aiohttp.ClientSession(timeout=self.timeout, headers=self.headers) as session:
            for scheme in schemes_to_try:
                target = f"{scheme}://{base_url}"
                if target.endswith('/'): target = target[:-1]
                
                current_proxy = self.get_next_proxy()

                if self.args.debug:
                    tqdm.write(f"{Fore.BLUE}[DEBUG] Probing: {target} | Proxy: {current_proxy}")

                try:
                    async with session.head(target, allow_redirects=True, proxy=current_proxy) as resp:
                        valid_urls.append(str(resp.url))
                        if self.args.debug:
                            tqdm.write(f"{Fore.GREEN}[DEBUG] Alive (HEAD): {target} -> {resp.url}")
                except Exception as e_head:
                    if self.args.debug:
                        tqdm.write(f"{Fore.MAGENTA}[DEBUG] HEAD failed for {target}: {e_head}. Trying GET...")
                    try:
                        async with session.get(target, allow_redirects=True, proxy=current_proxy) as resp:
                            valid_urls.append(str(resp.url))
                            if self.args.debug:
                                tqdm.write(f"{Fore.GREEN}[DEBUG] Alive (GET): {target} -> {resp.url}")
                    except Exception as e_get:
                        if self.args.debug:
                            tqdm.write(f"{Fore.RED}[DEBUG] Failed {target}: {e_get}")
                        continue
        
        return list(set(valid_urls))

    def generate_payloads(self, target_url):
        parsed = urlparse(target_url)
        host = parsed.netloc
        if ":" in host: 
            host = host.split(":")[0]

        payloads = [
            "evil.com",
            f"{host}.evil.com",
            "null",
            "*",
            f"{host}evil.com",
            f"evil.com{host}"
        ]
        
        # NOTE: Custom origins are handled in scan_url batches, not here.
        return list(set(payloads))

    async def scan_url(self, url, pbar=None):
        domain = get_domain_from_url(url)
        
        # Optimization: We usually skip if domain is known vulnerable to avoid spam,
        # BUT we must ensure the custom list is checked.
        # So we only skip "Default Batch" if vulnerable, but "Custom Batch" runs regardless.
        
        if url in SCANNED_URLS:
            if pbar: pbar.update(1)
            return
        SCANNED_URLS.add(url)

        # Batch 1: Default Payloads
        default_origins = self.generate_payloads(url)
        
        # Batch 2: Custom Origins (if any)
        scan_batches = [('default', default_origins)]
        
        if self.custom_origins:
            scan_batches.append(('custom', self.custom_origins))

        if self.args.debug:
            tqdm.write(f"{Fore.BLUE}[DEBUG] Target: {url} | Batches: {len(scan_batches)}")

        async with self.semaphore:
            async with aiohttp.ClientSession(timeout=self.timeout, headers=self.headers) as session:
                
                for batch_type, origins_list in scan_batches:
                    
                    # If we found a vuln in this domain using defaults, skip remaining defaults.
                    if batch_type == 'default' and domain in VULNERABLE_DOMAINS:
                        continue
                    
                    # Custom batch ALWAYS runs.
                    
                    for origin in origins_list:
                        # Optimization inside default batch
                        if batch_type == 'default' and domain in VULNERABLE_DOMAINS:
                            break
                            
                        request_headers = self.headers.copy()
                        request_headers['Origin'] = origin
                        
                        cors_found = False
                        methods = ['OPTIONS', 'HEAD', 'GET', 'POST']
                        
                        for method in methods:
                            current_proxy = self.get_next_proxy()
                            
                            if self.args.debug:
                                tqdm.write(f"{Fore.BLUE}[DEBUG] REQ: {method} {url} | Origin: {origin} | Proxy: {current_proxy}")

                            try:
                                req_func = getattr(session, method.lower())
                                async with req_func(url, headers=request_headers, allow_redirects=True, proxy=current_proxy) as response:
                                    
                                    acao = response.headers.get('Access-Control-Allow-Origin', '')
                                    acac = response.headers.get('Access-Control-Allow-Credentials', '').lower()
                                    # Capture Access-Control-Allow-Headers
                                    acah = response.headers.get('Access-Control-Allow-Headers', '')
                                    
                                    if self.args.debug:
                                        tqdm.write(f"{Fore.WHITE}[DEBUG] RESP: {response.status} | ACAO: '{acao}' | ACAC: '{acac}' | ACAH: '{acah}'")

                                    if acao:
                                        cors_found = True
                                        is_vuln = False
                                        
                                        # 1. Reflected Origin + ACAC
                                        if origin != "null" and origin != "*":
                                            if (origin in acao) and (acac == 'true'):
                                                is_vuln = True
                                        
                                        # 2. Null
                                        if origin == "null":
                                            if ('null' in acao or '*' in acao) and (acac == 'true'):
                                                is_vuln = True
                                                
                                        # 3. Wildcard * + ACAC True
                                        if '*' == acao and acac == 'true':
                                            is_vuln = True

                                        # 4. List injection
                                        if ',' in acao:
                                            parts = [p.strip() for p in acao.split(',')]
                                            if origin in parts and acac == 'true':
                                                is_vuln = True

                                        if is_vuln:
                                            if self.args.debug:
                                                tqdm.write(f"{Fore.RED}[DEBUG] >>> VULNERABILITY CONFIRMED <<<")
                                            
                                            # Pass ACAH to report function
                                            await self.report_vulnerability(url, method, origin, acao, acac, acah)
                                            VULNERABLE_DOMAINS.add(domain)
                                            
                                            # Stop methods loop for this origin
                                            break 
                                
                            except Exception as e:
                                if self.args.debug:
                                    tqdm.write(f"{Fore.RED}[DEBUG] Error {method} {url}: {e}")
                                continue
                        
                            if cors_found:
                                break # Stop trying other methods for this Origin
                        
                        # Loop Logic:
                        # If in default batch and vuln found, we stop defaults.
                        if batch_type == 'default' and domain in VULNERABLE_DOMAINS:
                            break
                        
                        # If in custom batch, we check specific custom logic.
                        # Usually we want to test ALL custom origins provided by user, 
                        # so we DO NOT break the loop here for 'custom'.
                        # (Unless you want to stop after the first successful custom payload)

        if pbar: pbar.update(1)

    async def report_vulnerability(self, url, method, origin, acao, acac, acah):
        domain = get_domain_from_url(url)
        
        # --- DEDUPLICATION LOGIC ---
        # We create a signature based on the Domain (not full URL), Origin, and Response headers.
        # This prevents reporting the same vuln for http://site and https://site
        vuln_signature = (domain, origin, method, acao, acac, acah)
        
        if vuln_signature in REPORTED_SIGNATURES:
            if self.args.debug:
                tqdm.write(f"{Fore.MAGENTA}[DEBUG] Duplicate finding suppressed for {domain} / {origin}")
            return # Skip reporting
        
        REPORTED_SIGNATURES.add(vuln_signature)
        
        # Format for silent/file
        clean_output = f"{url} | Method: {method} | ACAO: {acao}; ACAC: {acac}"
        if acah:
            clean_output += f"; ACAH: {acah}"
        
        # Display Logic
        if self.args.silent:
            tqdm.write(clean_output)
        else:
            tqdm.write(f"\n{Fore.RED}[+] VULNERABILITY FOUND!{Style.RESET_ALL}")
            tqdm.write(f"{Fore.GREEN}URL: {Fore.WHITE}{url}")
            tqdm.write(f"{Fore.GREEN}Origin Used: {Fore.WHITE}{origin}")
            tqdm.write(f"{Fore.GREEN}Method: {Fore.WHITE}{method}")
            tqdm.write(f"{Fore.YELLOW}ACAO: {Fore.WHITE}{acao}")
            tqdm.write(f"{Fore.YELLOW}ACAC: {Fore.WHITE}{acac}")
            if acah:
                tqdm.write(f"{Fore.YELLOW}ACAH: {Fore.WHITE}{acah}")
            tqdm.write("-" * 50)

        # File Output
        if self.args.output:
            async with aiofiles.open(self.args.output, 'a', encoding='utf-8') as f:
                await f.write(clean_output + "\n")

# --- Crawler Class ---

class Crawler:
    def __init__(self, scanner_instance):
        self.scanner = scanner_instance
        self.visited = set()
        
    async def extract_links(self, url):
        links = set()
        current_proxy = self.scanner.get_next_proxy()
        
        if self.scanner.args.debug:
            tqdm.write(f"{Fore.BLUE}[DEBUG] Crawling source: {url}")

        try:
            async with aiohttp.ClientSession(timeout=self.scanner.timeout, headers=self.scanner.headers) as session:
                async with session.get(url, allow_redirects=True, proxy=current_proxy) as resp:
                    if resp.status != 200:
                        if self.scanner.args.debug:
                            tqdm.write(f"{Fore.MAGENTA}[DEBUG] Crawl skipped {url}, status {resp.status}")
                        return links
                    html = await resp.text()
                    
            soup = BeautifulSoup(html, 'html.parser')
            
            # Tags to extract
            tags = {
                'a': 'href',
                'script': 'src',
                'link': 'href',
                'iframe': 'src',
                'form': 'action'
            }
            
            for tag, attr in tags.items():
                for element in soup.find_all(tag):
                    val = element.get(attr)
                    if val:
                        full_url = urljoin(url, val)
                        if get_domain_from_url(url) == get_domain_from_url(full_url):
                            normalized = normalize_url(full_url)
                            links.add(normalized)
            
            if self.scanner.args.debug:
                tqdm.write(f"{Fore.CYAN}[DEBUG] Extracted {len(links)} links from {url}")

        except Exception as e:
            if self.scanner.args.debug:
                tqdm.write(f"{Fore.RED}[DEBUG] Crawl Error {url}: {e}")
        
        return links

    async def start(self, base_urls):
        if not self.scanner.args.silent:
            print(f"{Fore.CYAN}[*] Starting Crawler...{Style.RESET_ALL}")
        
        all_endpoints = set()
        
        progress = None
        bar_fmt = "{desc}: {percentage:3.0f}% | {n_fmt}/{total_fmt} pages"
        
        if not self.scanner.args.silent or (self.scanner.args.silent and self.scanner.args.verbose):
             progress = tqdm(total=len(base_urls), desc="Crawling", unit="page", bar_format=bar_fmt)

        for url in base_urls:
            endpoints = await self.extract_links(url)
            all_endpoints.add(normalize_url(url))
            all_endpoints.update(endpoints)
            if progress: progress.update(1)
            
        if progress: progress.close()

        # Save crawled output
        if self.scanner.args.output_crawl:
            async with aiofiles.open(self.scanner.args.output_crawl, 'w', encoding='utf-8') as f:
                for link in all_endpoints:
                    await f.write(link + "\n")
        
        if not self.scanner.args.silent:
            print(f"{Fore.CYAN}[*] Crawling finished. Found {len(all_endpoints)} unique endpoints.{Style.RESET_ALL}")
            
        return list(all_endpoints)

# --- Main Execution ---

async def main():
    parser = argparse.ArgumentParser(description="CORSAIR-X | Advanced CORS Scanner", add_help=False)
    
    # Groups
    target_group = parser.add_argument_group('Target')
    target_group.add_argument('-u', '--url', help="Single Target URL")
    target_group.add_argument('-l', '--list', help="List of Target URLs (file)")
    
    scan_group = parser.add_argument_group('Scanning Configuration')
    scan_group.add_argument('--crawl', action='store_true', help="Crawl endpoints from the target(s) source code")
    scan_group.add_argument('--origins', help="Custom origins (string or file path)")
    scan_group.add_argument('-H', '--custom-header', action='append', help="Custom headers (e.g., 'Cookie: value')")
    scan_group.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, help="Request timeout (seconds)")
    scan_group.add_argument('--concurrency', type=int, default=DEFAULT_CONCURRENCY, help="Concurrent requests")
    
    # Proxy Group
    proxy_group = parser.add_argument_group('Proxy Configuration')
    proxy_group.add_argument('-p', '--proxy', help="Single Proxy (e.g., http://127.0.0.1:8080)")
    proxy_group.add_argument('-pf', '--proxy-file', help="File containing list of proxies")
    
    out_group = parser.add_argument_group('Output')
    out_group.add_argument('-o', '--output', help="Save vulnerable URLs to file")
    out_group.add_argument('-oC', '--output-crawl', help="Save crawled URLs to file")
    out_group.add_argument('-s', '--silent', action='store_true', help="Silent mode (only vulns)")
    out_group.add_argument('-v', '--verbose', action='store_true', help="Show progress in silent mode")
    out_group.add_argument('--debug', action='store_true', help="Deep Debug mode (trace all steps)")
    
    misc_group = parser.add_argument_group('Misc')
    misc_group.add_argument('-h', '--help', action='help', help="Show this help message")

    args = parser.parse_args()

    if not args.silent:
        print_banner()

    if not args.url and not args.list:
        parser.print_help()
        sys.exit(1)

    scanner = CORSScanner(args)
    
    # 1. Prepare Targets
    raw_targets = []
    if args.url:
        raw_targets.append(args.url)
    if args.list:
        try:
            with open(args.list, 'r') as f:
                raw_targets.extend([line.strip() for line in f if line.strip()])
        except Exception as e:
            print(f"{Fore.RED}[!] Error reading list file: {e}")
            sys.exit(1)

    # 2. Protocol Intelligence (HTTP vs HTTPS)
    if not args.silent:
        print(f"{Fore.YELLOW}[*] Resolving protocols for {len(raw_targets)} raw inputs...{Style.RESET_ALL}")
    
    final_targets = []
    
    show_progress = not args.silent or (args.silent and args.verbose)
    bar_fmt = "{desc}: {percentage:3.0f}% | {n_fmt}/{total_fmt} targets"

    results = []
    
    # Resolve protocols async
    tasks = [scanner.get_smart_protocols(t) for t in raw_targets]
    if show_progress:
        for f in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Resolving Protocols", bar_format=bar_fmt):
            res = await f
            results.extend(res)
    else:
        results_list = await asyncio.gather(*tasks)
        for res in results_list:
            results.extend(res)
            
    final_targets = list(set(results))

    if not args.silent:
        print(f"{Fore.GREEN}[+] {len(final_targets)} Live targets ready.{Style.RESET_ALL}")

    # 3. Crawling (if enabled)
    scan_list = final_targets
    if args.crawl:
        crawler = Crawler(scanner)
        scan_list = await crawler.start(final_targets)

    # 4. Scanning
    if not args.silent:
        print(f"{Fore.YELLOW}[*] Starting Scan on {len(scan_list)} endpoints...{Style.RESET_ALL}")

    pbar = None
    if show_progress:
        scan_bar_fmt = "{desc}: {percentage:3.0f}% | {n_fmt}/{total_fmt} URLs"
        pbar = tqdm(total=len(scan_list), desc="Scanning", unit="url", bar_format=scan_bar_fmt)

    scan_tasks = [scanner.scan_url(url, pbar) for url in scan_list]
    await asyncio.gather(*scan_tasks)
    
    if pbar:
        pbar.close()
        
    if not args.silent:
        print(f"\n{Fore.CYAN}Scan Complete.{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Please wait for shutting down...{Style.RESET_ALL}")
        # Cleanly exiting
        sys.exit(0)
