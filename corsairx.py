#!/usr/bin/env python3
import sys
import asyncio
import aiohttp
import argparse
import re
import itertools
import warnings
from urllib.parse import urlparse, urljoin, urlunparse
from colorama import Fore, Style, init
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
import aiofiles
from tqdm.asyncio import tqdm

# Initialize Colorama
init(autoreset=True)

# --- Suppress XML Parsed as HTML Warning ---
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

# --- Configuration & Constants ---
DEFAULT_TIMEOUT = 10
DEFAULT_CONCURRENCY = 20
CRAWL_DEPTH = 3  # Depth of recursive crawling
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# Global Sets for Deduplication and Skip Logic
VULNERABLE_DOMAINS = set()
SCANNED_URLS = set()
CRAWLED_URLS = set()
# Set to store signatures of reported vulns to prevent duplicates across http/https
REPORTED_SIGNATURES = set()

# --- FILTER CONFIGURATION ---
# Extensions to ignore during scanning/crawling output (Media, CSS, Fonts, etc.)
IGNORED_EXTENSIONS = {
    # Images
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.webp', '.tiff',
    # Audio/Video
    '.mp3', '.mp4', '.avi', '.mov', '.mkv', '.wav', '.flv', '.wmv',
    # Documents/Archives
    '.pdf', '.zip', '.tar', '.gz', '.rar', '.7z', '.doc', '.docx', '.xls', '.xlsx',
    # Web Assets (We ignore these for CORS scanning, but we might parse JS/CSS in Smart Crawl)
    '.css', '.map', '.less', '.scss',
    '.woff', '.woff2', '.ttf', '.eot', '.otf'
}

# Extensions that we specifically want to download and parse for hidden endpoints
INTERESTING_ASSETS = {
    '.js', '.json', '.xml', '.txt', '.conf', '.ini', '.config', '.env', '.ts', '.jsx', '.tsx'
}


# (?::\d+)? to capture optional port numbers
REGEX_URL = r"https?://[a-zA-Z0-9.-]+(?::\d+)?(?:/[^\s'\"<>]*)?"

# Matches relative paths inside quotes e.g. "/api/v1/user" or 'v1/data' or './config'
# Capture paths starting with / or ./ or ../
REGEX_PATH = r"['\"](\s*(?:/|\.\.?/)[a-zA-Z0-9_?&=/\-\.]+)\s*['\"]"

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
           Enhanced with Smart JS & Port Analysis
    ====================================================={Style.RESET_ALL}
    """
    print(banner)

def get_domain_from_url(url):
    try:
        parsed = urlparse(url)
        # netloc includes domain and port (e.g., example.com:8080)
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

def is_static_asset(url):
    """Checks if the URL ends with an ignored extension (for Scanning purposes)."""
    try:
        parsed = urlparse(url)
        path = parsed.path.lower()
        return any(path.endswith(ext) for ext in IGNORED_EXTENSIONS)
    except:
        return False

def is_interesting_asset(url):
    """Checks if the URL is a JS/Config file worth parsing."""
    try:
        parsed = urlparse(url)
        path = parsed.path.lower()
        return any(path.endswith(ext) for ext in INTERESTING_ASSETS)
    except:
        return False

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
                split_headers = header_input.split(";")
                for h in split_headers:
                    if ":" in h:
                        k, v = h.split(":", 1)
                        self.headers[k.strip()] = v.strip()
            
            if self.args.debug:
                tqdm.write(f"{Fore.BLUE}[DEBUG] Custom Headers Loaded: {self.headers}")

        # Load custom origins
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
        
        self.proxy_pool = itertools.cycle(self.proxies) if self.proxies else None

    def get_next_proxy(self):
        if self.proxy_pool:
            p = next(self.proxy_pool)
            return p
        return None

    async def get_smart_protocols(self, raw_url):
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
            # parsed.netloc handles ports automatically (e.g. example.com:8080)
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
        # If port exists (example.com:8080), we strip it for the payload domain
        # because "example.com:8080.evil.com" is usually invalid, we want "example.com.evil.com"
        if ":" in host: 
            host = host.split(":")[0]

        payloads = [
            "evil.com",
            f"{host}.evil.com",
            "null",
            "*",
            f"{host}evil.com"
        ]
        return list(set(payloads))

    async def scan_url(self, url, pbar=None):
        domain = get_domain_from_url(url)
        
        # Deduplication check
        if url in SCANNED_URLS:
            if pbar: pbar.update(1)
            return
        SCANNED_URLS.add(url)

        default_origins = self.generate_payloads(url)
        scan_batches = [('default', default_origins)]
        
        if self.custom_origins:
            scan_batches.append(('custom', self.custom_origins))

        if self.args.debug:
            tqdm.write(f"{Fore.BLUE}[DEBUG] Target: {url} | Batches: {len(scan_batches)}")

        async with self.semaphore:
            async with aiohttp.ClientSession(timeout=self.timeout, headers=self.headers) as session:
                
                for batch_type, origins_list in scan_batches:
                    
                    if batch_type == 'default' and domain in VULNERABLE_DOMAINS:
                        continue
                    
                    for origin in origins_list:
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
                                    acah = response.headers.get('Access-Control-Allow-Headers', '')
                                    
                                    if self.args.debug:
                                        tqdm.write(f"{Fore.WHITE}[DEBUG] RESP: {response.status} | ACAO: '{acao}' | ACAC: '{acac}' | ACAH: '{acah}'")

                                    if acao:
                                        cors_found = True
                                        is_vuln = False
                                        
                                        if origin != "null" and origin != "*":
                                            if (origin in acao) and (acac == 'true'):
                                                is_vuln = True
                                        
                                        if origin == "null":
                                            if ('null' in acao or '*' in acao) and (acac == 'true'):
                                                is_vuln = True
                                                
                                        if '*' == acao and acac == 'true':
                                            is_vuln = True

                                        if ',' in acao:
                                            parts = [p.strip() for p in acao.split(',')]
                                            if origin in parts and acac == 'true':
                                                is_vuln = True

                                        if is_vuln:
                                            if acah and not self.args.acah:
                                                if self.args.debug:
                                                    tqdm.write(f"{Fore.MAGENTA}[DEBUG] Ignored vuln due to ACAH presence (Default).")
                                                is_vuln = False
                                            
                                            if is_vuln:
                                                if self.args.debug:
                                                    tqdm.write(f"{Fore.RED}[DEBUG] >>> VULNERABILITY CONFIRMED <<<")
                                                
                                                await self.report_vulnerability(url, method, origin, acao, acac, acah)
                                                VULNERABLE_DOMAINS.add(domain)
                                                break 
                                
                            except Exception as e:
                                if self.args.debug:
                                    tqdm.write(f"{Fore.RED}[DEBUG] Error {method} {url}: {e}")
                                continue
                        
                            if cors_found:
                                break
                        
                        if batch_type == 'default' and domain in VULNERABLE_DOMAINS:
                            break

        if pbar: pbar.update(1)

    async def report_vulnerability(self, url, method, origin, acao, acac, acah):
        domain = get_domain_from_url(url)
        vuln_signature = (domain, origin, method, acao, acac, acah)
        
        if vuln_signature in REPORTED_SIGNATURES:
            if self.args.debug:
                tqdm.write(f"{Fore.MAGENTA}[DEBUG] Duplicate finding suppressed for {domain} / {origin}")
            return
        
        REPORTED_SIGNATURES.add(vuln_signature)
        
        clean_output = f"{url} | Method: {method} | ACAO: {acao}; ACAC: {acac}"
        if acah:
            clean_output += f"; ACAH: {acah}"
        
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

        if self.args.output:
            async with aiofiles.open(self.args.output, 'a', encoding='utf-8') as f:
                await f.write(clean_output + "\n")

# --- Crawler Class ---

class Crawler:
    def __init__(self, scanner_instance):
        self.scanner = scanner_instance
        self.visited = set()
        self.processed_assets = set() 
        
    async def parse_asset_content(self, url):
        """Fetches and parses JS/JSON/TXT files for hidden endpoints."""
        if url in self.processed_assets:
            return set()
        self.processed_assets.add(url)
        
        extracted = set()
        current_proxy = self.scanner.get_next_proxy()
        
        if self.scanner.args.debug:
            tqdm.write(f"{Fore.YELLOW}[DEBUG] Analyzing Asset: {url}")
            
        try:
            async with aiohttp.ClientSession(timeout=self.scanner.timeout, headers=self.scanner.headers) as session:
                async with session.get(url, allow_redirects=True, proxy=current_proxy) as resp:
                    if resp.status != 200:
                        return extracted
                    
                    content = await resp.text(errors='ignore')
                    
                    # 1. Regex for Absolute URLs (Now supports Ports!)
                    found_urls = re.findall(REGEX_URL, content)
                    for item in found_urls:
                        if get_domain_from_url(item):
                            extracted.add(item)
                            
                    # 2. Regex for Relative Paths
                    found_paths = re.findall(REGEX_PATH, content)
                    base_parsed = urlparse(url)
                    base_root = f"{base_parsed.scheme}://{base_parsed.netloc}"
                    
                    for path in found_paths:
                        path = path.strip()
                        path = path.strip('"').strip("'")
                        
                        if len(path) > 1 and not " " in path and not "\n" in path:
                            # Handle relative paths correctly even if they don't start with http
                            try:
                                full_asset_url = urljoin(base_root, path)
                                # Validate the result looks like a URL
                                if full_asset_url.startswith("http"):
                                    extracted.add(full_asset_url)
                            except:
                                pass

            if self.scanner.args.debug and len(extracted) > 0:
                tqdm.write(f"{Fore.GREEN}[DEBUG] Found {len(extracted)} items in {url}")

        except Exception as e:
            if self.scanner.args.debug:
                tqdm.write(f"{Fore.RED}[DEBUG] Asset Parse Error {url}: {e}")
                
        return extracted

    async def extract_links(self, url):
        links = set()
        
        if url in self.visited:
            return links
        self.visited.add(url)

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
                    html = await resp.text(errors='ignore')
                    
            soup = BeautifulSoup(html, 'html.parser')
            
            tags = {
                'a': 'href',
                'script': 'src',
                'link': 'href',
                'iframe': 'src',
                'form': 'action',
                'img': 'src',
                'source': 'src'
            }
            
            potential_assets_to_scan = set()

            for tag, attr in tags.items():
                for element in soup.find_all(tag):
                    val = element.get(attr)
                    if val:
                        # urljoin handles relative paths (e.g. /api/v1) by merging with base URL
                        full_url = urljoin(url, val)
                        
                        if is_interesting_asset(full_url):
                            potential_assets_to_scan.add(full_url)
                        
                        if is_static_asset(full_url):
                            if self.scanner.args.debug:
                                tqdm.write(f"{Fore.MAGENTA}[DEBUG] Filtered static asset from Scan Target: {full_url}")
                        else:
                            # Only crawl/add if same domain to prevent scope creep
                            if get_domain_from_url(url) == get_domain_from_url(full_url):
                                normalized = normalize_url(full_url)
                                links.add(normalized)
            
            # Smart Asset Parsing (Async)
            if potential_assets_to_scan:
                if self.scanner.args.debug:
                    tqdm.write(f"{Fore.CYAN}[DEBUG] Analyzing {len(potential_assets_to_scan)} assets for hidden endpoints...")
                
                asset_tasks = [self.parse_asset_content(asset) for asset in potential_assets_to_scan]
                results = await asyncio.gather(*asset_tasks)
                
                for res_set in results:
                    for extracted_url in res_set:
                        # Ensure extracted URLs from JS also respect domain scope but allow subdomains if needed
                        # For strictly same domain:
                        if get_domain_from_url(url) == get_domain_from_url(extracted_url):
                            if not is_static_asset(extracted_url):
                                links.add(normalize_url(extracted_url))
            
            if self.scanner.args.debug:
                tqdm.write(f"{Fore.CYAN}[DEBUG] Extracted {len(links)} links (total) from {url}")

        except Exception as e:
            if self.scanner.args.debug:
                tqdm.write(f"{Fore.RED}[DEBUG] Crawl Error {url}: {e}")
        
        return links

    async def start(self, base_urls):
        if not self.scanner.args.silent:
            print(f"{Fore.CYAN}[*] Starting Deep Recursive Crawler (Max Depth: {CRAWL_DEPTH})...{Style.RESET_ALL}")
        
        all_endpoints = set()
        # Initialize with base URLs
        for u in base_urls:
            all_endpoints.add(normalize_url(u))
        
        current_batch = list(set(base_urls))
        visited_urls = set()
        
        # Recursive Crawling Logic (BFS)
        for depth in range(CRAWL_DEPTH):
            if not current_batch:
                break
            
            if not self.scanner.args.silent:
                 tqdm.write(f"{Fore.YELLOW}[*] Crawling Depth {depth + 1}: Processing {len(current_batch)} URLs...{Style.RESET_ALL}")

            tasks = []
            for url in current_batch:
                if url not in visited_urls:
                    tasks.append(self.extract_links(url))
                    visited_urls.add(url)
            
            if not tasks:
                break
                
            # Run batch
            results = await asyncio.gather(*tasks)
            
            # Collect new links for next batch
            next_batch = set()
            for res_links in results:
                for link in res_links:
                    all_endpoints.add(link)
                    if link not in visited_urls:
                        next_batch.add(link)
            
            current_batch = list(next_batch)

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
    
    target_group = parser.add_argument_group('Target')
    target_group.add_argument('-u', '--url', help="Single Target URL")
    target_group.add_argument('-l', '--list', help="List of Target URLs (file)")
    
    scan_group = parser.add_argument_group('Scanning Configuration')
    scan_group.add_argument('--crawl', action='store_true', help="Crawl endpoints (includes Smart JS/Asset analysis)")
    scan_group.add_argument('--origins', help="Custom origins (string or file path)")
    scan_group.add_argument('-H', '--custom-header', action='append', help="Custom headers (e.g., 'Cookie: value')")
    scan_group.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, help="Request timeout (seconds)")
    scan_group.add_argument('--concurrency', type=int, default=DEFAULT_CONCURRENCY, help="Concurrent requests")
    scan_group.add_argument('--acah', action='store_true', help="Include vulnerability even if Access-Control-Allow-Headers is present (Default: Skip)")
    
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

    # --- PHASE 1: Scan ROOT Domains ---
    if not args.silent:
        print(f"{Fore.YELLOW}[*] Phase 1: Scanning {len(final_targets)} Root Targets...{Style.RESET_ALL}")
    
    pbar_root = None
    if show_progress:
        scan_bar_fmt = "{desc}: {percentage:3.0f}% | {n_fmt}/{total_fmt} Roots"
        pbar_root = tqdm(total=len(final_targets), desc="Scanning Roots", unit="url", bar_format=scan_bar_fmt)

    root_tasks = [scanner.scan_url(url, pbar_root) for url in final_targets]
    await asyncio.gather(*root_tasks)
    
    if pbar_root:
        pbar_root.close()

    # --- PHASE 2: Crawling & Scanning Children ---
    if args.crawl:
        crawler = Crawler(scanner)
        
        all_crawled = await crawler.start(final_targets)
        
        new_targets = [u for u in all_crawled if u not in SCANNED_URLS]
        
        if new_targets:
            if not args.silent:
                print(f"{Fore.YELLOW}[*] Phase 2: Scanning {len(new_targets)} Crawled Endpoints...{Style.RESET_ALL}")

            pbar_crawl = None
            if show_progress:
                scan_bar_fmt = "{desc}: {percentage:3.0f}% | {n_fmt}/{total_fmt} URLs"
                pbar_crawl = tqdm(total=len(new_targets), desc="Scanning Crawled", unit="url", bar_format=scan_bar_fmt)

            crawl_tasks = [scanner.scan_url(url, pbar_crawl) for url in new_targets]
            await asyncio.gather(*crawl_tasks)
            
            if pbar_crawl:
                pbar_crawl.close()
        else:
             if not args.silent:
                print(f"{Fore.CYAN}[*] No new unique endpoints found to scan.{Style.RESET_ALL}")

    if not args.silent:
        print(f"\n{Fore.CYAN}Scan Complete.{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Please wait for shutting down...{Style.RESET_ALL}")
        sys.exit(0)
