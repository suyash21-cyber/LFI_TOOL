LFI_TOOL is a powerful and fast Local File Inclusion (LFI) vulnerability scanner. It goes beyond simple pattern matching by incorporating parameter discovery, differential analysis, and support for both GET and POST requests.

It's designed for penetration testers and bug bounty hunters to quickly identify LFI vulnerabilities by intelligently comparing web server responses against a baseline.

Key Features
🔎 Automatic Parameter Discovery: Crawls URLs to find GET parameters and input fields (input, textarea, select) within HTML forms for both GET and POST methods.
🎯 Differential Analysis: Establishes a "normal" baseline response for each parameter and then identifies vulnerabilities by detecting significant deviations in content length and MD5 hash after injecting payloads.
📂 Custom Payloads: Use the built-in, curated payload list or supply your own file of LFI payloads for tailored testing.
** decoding:** Automatically decodes responses for payloads using php://filter/convert.base64-encode and checks for vulnerability indicators in the decoded content.
⚡ Fast & Concurrent: Utilizes multithreading to perform scans quickly across many URLs and parameters.
🍪 Authenticated Scans: Supports authenticated testing by allowing you to provide a cookie string.
🌐 Proxy Support: Route all traffic through a proxy like Burp Suite or ZAP for inspection and debugging.
📝 Flexible Output: Saves all findings to a clean, organized text file.

RUN TOOL
python3 lfi_scanner.py -f urls.txt

