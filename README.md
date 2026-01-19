# 🔥 XSS SCAN — Advanced XSS Vulnerability Scanner

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/License-Educational-red?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-success?style=for-the-badge" alt="Platform"/>
  <img src="https://img.shields.io/badge/WAF%20Detection-160%2B-purple?style=for-the-badge" alt="WAF Detection"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Payloads-350%2B-orange?style=for-the-badge" alt="Payloads"/>
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge" alt="Status"/>
</p>

---

```
╔═════════════════════════════════════════════════════════════════════╗
║  ≋★                                                          ★≋   ║
║   ██╗  ██╗███████╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗➤  ║
║   ╚██╗██╔╝██╔════╝██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║    ║
║    ╚███╔╝ ███████╗███████╗    ███████╗██║     ███████║██╔██╗ ██║➤  ║
║    ██╔██╗ ╚════██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║    ║
║   ██╔╝ ██╗███████║███████║    ███████║╚██████╗██║  ██║██║ ╚████║➤  ║
║   ╚═╝  ╚═╝╚══════╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝    ║
║                                                                     ║
║        ⚡ Advanced XSS Vulnerability Scanner ⚡                    ║
╚═════════════════════════════════════════════════════════════════════╝
```

## 📖 Overview

**XSS SCAN** is a powerful, feature-rich Cross-Site Scripting (XSS) vulnerability scanner designed for security professionals and penetration testers. It automatically discovers endpoints, parameters, and tests XSS payloads with advanced WAF bypass capabilities.

> ⚠️ **Disclaimer:** This tool is intended for **authorized security testing only**. Unauthorized use against websites without explicit permission is illegal and unethical.

---

## ✨ Key Features

### 🎯 **Comprehensive XSS Detection**
- **Reflected XSS** — Detects input reflection in HTTP responses
- **DOM-based XSS** — Analyzes JavaScript sinks and sources
- **Stored XSS** — Deep scan mode for persistent XSS (with `--deep-scan`)
- **Blind XSS** — Support for out-of-band testing

### 🔍 **Smart Parameter Discovery**
- 🕸️ Automatic web crawling with configurable depth
- 📚 Wayback Machine integration for historical endpoints
- 🗺️ Robots.txt & sitemap.xml parsing
- 🔄 Reflective parameter mining
- 💪 Parameter brute-forcing with 50+ common XSS-prone parameters
- 🚀 Enhanced auto-crawl for PHP MVC endpoints

### 🛡️ **Advanced WAF Detection & Bypass**
- 🔎 Detects **160+ WAF signatures** including:
  - Cloudflare, Akamai, AWS WAF, Azure WAF, Google Cloud Armor
  - F5 BIG-IP, Fortinet, Imperva/Incapsula, Citrix NetScaler
  - ModSecurity, Sucuri, Barracuda, and many more!
- ⚔️ **100+ WAF bypass payloads** for advanced evasion

### 🚀 **350+ Built-in XSS Payloads**
- Basic script injection
- Event handler payloads
- SVG-based attacks
- Mutation XSS (mXSS)
- Encoded payloads (HTML entities, URL, Unicode)
- Case variation bypass
- Template injection
- Polyglot payloads
- And many more!

---

## 🔧 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Quick Install

```bash
# Clone or download the project
git clone https://github.com/subhajit-sudo/xss-scanner.git
cd xss-scanner

# Install dependencies
pip install -r requirements.txt
```

### Manual Dependency Installation

```bash
pip install requests beautifulsoup4 colorama urllib3
```

---

## 🚀 Usage

### Basic Scan

```bash
# Simple scan with default settings
python xss_scanner.py example.com

# Scan with HTTPS
python xss_scanner.py https://example.com
```

### Advanced Options

```bash
# Deep scan with increased crawl depth and verbose output
python xss_scanner.py example.com -d 5 -v

# Use custom payloads from file
python xss_scanner.py example.com -p custom_payloads.txt

# Enable WAF bypass mode
python xss_scanner.py example.com --waf-bypass

# Test all payloads (don't stop at first match)
python xss_scanner.py example.com --all-payloads

# Enhanced PHP MVC endpoint discovery
python xss_scanner.py example.com --auto-crawl

# Comprehensive deep scan
python xss_scanner.py example.com --deep-scan
```

### View Available Options

```bash
# Show all XSS payloads
python xss_scanner.py --show-payloads

# Show WAF bypass payloads
python xss_scanner.py --show-waf-payloads

# Show all detectable WAFs
python xss_scanner.py --show-wafs
```

---

## ⚙️ Command Line Options

| Option | Description |
|--------|-------------|
| `domain` | Target domain to scan (e.g., example.com) |
| `-d, --depth` | Maximum crawl depth (default: 3) |
| `-t, --timeout` | Request timeout in seconds (default: 10) |
| `-v, --verbose` | Enable verbose output |
| `-p, --payloads FILE` | Path to custom payload list file |
| `--all-payloads` | Test ALL payloads per parameter |
| `--waf-bypass` | Enable WAF bypass mode with advanced evasion payloads |
| `--show-payloads` | Show all available XSS payloads and exit |
| `--show-waf-payloads` | Show all WAF bypass payloads and exit |
| `--show-wafs` | Show all detectable WAFs (160+) and exit |
| `--deep-scan` | Enable comprehensive XSS testing |
| `--auto-crawl` | Enhanced auto-crawl for PHP MVC endpoints |
| `--no-brute-params` | Disable parameter brute-forcing |
| `--no-force-test` | Disable force testing of common XSS params |
| `--no-auto-crawl` | Disable PHP endpoint auto-crawl discovery |

---

## 📁 Project Structure

```
xss-scanner/
├── 📄 xss_scanner.py        # Main scanner script
├── 📄 requirements.txt      # Python dependencies
├── ├── 📄 sample_payloads.txt   # Example custom payloads
└── 📄 README.md             # This file
```

---

## 📝 Custom Payloads

Create your own payload file with one payload per line. Lines starting with `#` are treated as comments:

```text
# Custom XSS Payloads
# Basic payloads
<script>alert('XSS')</script>
<script>alert(document.cookie)</script>

# Event handlers
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>

# Encoded payloads
%3Cscript%3Ealert('XSS')%3C/script%3E
```

Usage:
```bash
python xss_scanner.py example.com -p my_payloads.txt
```

---

## 🛡️ WAF Detection

The scanner automatically detects and identifies **160+ WAF solutions**:

| Category | WAFs |
|----------|------|
| **Cloud/CDN** | Cloudflare, Akamai, AWS WAF, Azure WAF, Google Cloud Armor, Cloudfront |
| **Enterprise** | F5 BIG-IP, Fortinet, Imperva, Citrix NetScaler, Palo Alto, Check Point |
| **Open Source** | ModSecurity, NAXSI, OpenResty, Varnish |
| **Bot Protection** | PerimeterX, DataDome, Distil Networks, Kasada |
| **Chinese WAFs** | Alibaba WAF, Tencent WAF, Baidu WAF, Huawei WAF, and more |
| **CMS WAFs** | Wordfence, Sucuri, MalCare, Cloudflare for WordPress |

---

## 📊 Sample Output

```
╔══════════════════════════════════════════════════════════════════════╗
║                    📊 SCAN RESULTS SUMMARY                           ║
╠══════════════════════════════════════════════════════════════════════╣
║ Target:              https://example.com                             ║
║ Pages Crawled:       25                                              ║
║ Endpoints Found:     12                                              ║
║ Parameters Found:    47                                              ║
║ Total Tests Run:     16450                                           ║
║ Vulnerabilities:     3 ⚠️  VULNERABLE!                               ║
╚══════════════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════════════╗
║                    🚨 VULNERABILITIES DETECTED 🚨                    ║
╚══════════════════════════════════════════════════════════════════════╝

[1] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    URL:       https://example.com/search
    Parameter: q
    Method:    GET
    Payloads:  5 working
               • <script>alert(1)</script>
               • <img src=x onerror=alert(1)>
               • <svg onload=alert(1)>
               ... and 2 more
```

---

## 🔒 Responsible Disclosure

If you discover vulnerabilities during authorized testing:

1. **Document findings** with clear reproduction steps
2. **Report privately** to the asset owner
3. **Allow reasonable time** for remediation
4. **Do not disclose** until issues are fixed

---

## ⚠️ Legal Notice

```
This tool is provided for educational and authorized security testing purposes only.
The developer assumes NO responsibility for misuse or damage caused by this tool.

Before scanning any target:
✓ Obtain explicit written permission from the target owner
✓ Understand and comply with applicable laws and regulations
✓ Follow responsible disclosure practices
```

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. 🐛 Report bugs and issues
2. 💡 Suggest new features or payloads
3. 🔧 Submit pull requests
4. 📖 Improve documentation

---

## 👨‍💻 Author

<p align="center">
  <b>Crafted with ❤️ by Subhajit</b><br>
  <i>Cyber Security Enthusiast</i>
</p>

---

## 📜 License

This project is for **educational and authorized security testing purposes only**.

---

<p align="center">
  <img src="https://img.shields.io/badge/Made%20with-Python-blue?style=flat-square&logo=python" alt="Made with Python"/>
  <img src="https://img.shields.io/badge/Powered%20by-Coffee-brown?style=flat-square&logo=buymeacoffee" alt="Powered by Coffee"/>
</p>

<p align="center">
  ⭐ <b>Star this repo if you find it useful!</b> ⭐
</p>
