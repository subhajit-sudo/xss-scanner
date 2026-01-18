# XSS SCAN - Advanced XSS Vulnerability Scanner

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)

**XSS SCAN** is a powerful, multi-threaded XSS vulnerability scanner developed for security professionals and bug bounty hunters. It goes beyond simple signature matching by implementing advanced crawling, sophisticated WAF bypass techniques, and context-aware payload testing to discover Cross-Site Scripting vulnerabilities in modern web applications.

```
╔═════════════════════════════════════════════════════════════════════╗
║   ≋★                                                          ★≋    ║
║   ██╗  ██╗███████╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗    ║
║   ╚██╗██╔╝██╔════╝██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║    ║
║    ╚███╔╝ ███████╗███████╗    ███████╗██║     ███████║██╔██╗ ██║    ║
║    ██╔██╗ ╚════██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║    ║
║   ██╔╝ ██╗███████║███████║    ███████║╚██████╗██║  ██║██║ ╚████║    ║
║   ╚═╝  ╚═╝╚══════╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝    ║
║                                                                     ║
║   [+] Advanced XSS Vulnerability Scanner for Linux                  ║
║   [+] Automatic Parameter Discovery & Payload Testing               ║
║   [+] 40+ WAF Detection & Advanced Bypass Capabilities              ║
║   [+] Enhanced Auto-Crawl for PHP MVC Endpoints                     ║
║                                                                     ║
║      </> Code by Subhajit - Security Research </>                   ║
║                                                                     ║
║           [!] For Authorized Security Testing Only [!]              ║
║   ≋★                                                          ★≋    ║
╚═════════════════════════════════════════════════════════════════════╝
```

## 🚀 Key Features

*   **Advanced WAF Detection & Bypass**:
    *   Detects **160+** Web Application Firewalls (Cloudflare, AWS, Akamai, Imperva, etc.).
    *   Includes a dedicated `--waf-bypass` mode with encoded and obfuscated payloads designed to slip past filters.
*   **Deep Parameter Discovery**:
    *   **Auto-Crawl for PHP MVC**: Specifically targets modern PHP frameworks to find hidden endpoints (e.g., `/index.php/user/view`).
    *   Mines parameters from HTML forms, JavaScript variables (AJAX, window.config), Data attributes, and even the **Wayback Machine**.
    *   Brute-forces common XSS query parameters to find hidden inputs.
*   **Intelligent Payloads**:
    *   Context-aware testing (polyglots, attribute breaking, script context breaking).
    *   Supports custom payload lists.
    *   Checks for reflections in specific HTML contexts (DOM XSS).
*   **Performance**:
    *   Multi-threaded architecture for fast scanning.
    *   Smart queue management to avoid redundant scans.

## 📦 Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/xss-scanner.git
    cd xss-scanner
    ```

2.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
    *(Requires `requests`, `beautifulsoup4`, `colorama`)*

## 🛠️ Usage

Basic scan of a single URL:
```bash
python xss_scanner.py http://testphp.vulnweb.com
```

Advanced scan with **WAF Bypass** and **Deep Crawling**:
```bash
python xss_scanner.py https://example.com --waf-bypass --deep-scan -d 5
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message and exit |
| `-d, --depth` | Maximum crawl depth (default: 3) |
| `-t, --timeout` | Request timeout in seconds |
| `-v, --verbose` | Enable verbose output (detailed logging) |
| `--waf-bypass` | **Enable WAF bypass mode** (highly recommended for protected sites) |
| `--auto-crawl` | Enable enhanced PHP MVC endpoint discovery (default: on) |
| `--show-wafs` | List all 160+ detectable WAF signatures |
| `-p, --payloads` | Load custom XSS payloads from a file |
| `--show-payloads` | Display all built-in payloads |

## 🛡️ Disclaimer

**This tool is for educational purposes and authorized security testing ONLY.**
Do not use this tool on websites you do not own or do not have explicit permission to test. The author is not responsible for any misuse or legal consequences resulting from the use of this tool.

---
*Code by Subhajit - Security Research*
