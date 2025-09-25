### Free Palestine

# Hunter

Hunter is a small Bash utility that scans an IPv4 range for common HTTP(S) ports using masscan, then probes discovered hosts/ports to extract reachable web URLs and basic page characteristics. It’s designed to quickly surface web-facing services.

## Features

- Fast port discovery with masscan (default ports: 80, 443, 3000, 8000, 8080, 8443, 8888).
- Extracts unique URLs from each discovered host using lynx.
- Filters out noisy/default vendor pages via a built-in blocklist.
- Saves a results file per IP-range in ./results/ containing found URLs and basic headers.
- Lightweight and easy to extend.

## Installation
```
# requirements
sudo apt install -y masscan jq lynx curl
sudo apt update

# usage
chmod +x hunter.sh
./hunter.sh
```
You will be prompted to enter an IP range
```
[x] Enter the IP range: 192.168.1.0/24
```
Results are saved in /results
```
===== Scan Summary =====
Date       : XXXXX
IP Range   : 192.168.1.0/24
========================
```
If no links found on the page, then the header is saved
```
 → Page responded with 302, size: 133 bytes (no links found)

=== HEADERS ===
HTTP/1.1 302 Found
Date: XXXXX
Server: CPWS
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: SAMEORIGIN
Location: /Login/Login
Pragma: no-cache
Cache-Control: no-store
Vary: User-Agent
Content-Length: 133
Content-Type: text/html; charset=UTF-8

===============
```
