\# Vulnerability Scanner



A lightweight Python recon scanner built from scratch with raw sockets. It finds open ports, grabs service banners, checks web security headers and saves a JSON report. It automates the early recon phase of a VAPT engagement.



\## Features



\- \*\*Port scanning:\*\* multi-threaded TCP connect scan of 15 common ports

\- \*\*Banner grabbing:\*\* reads service banners (SSH, FTP, SMTP, HTTP Server header) to spot outdated versions

\- \*\*Risky service warnings:\*\* flags exposed Telnet, FTP, SMB, RDP and database ports

\- \*\*HTTP security header check:\*\* reports missing CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy and HSTS, plus version disclosure in Server / X-Powered-By headers

\- \*\*JSON reports:\*\* every scan is saved as a timestamped file



\## Setup



&#x20;   git clone https://github.com/Thor-Loki7/vuln-scanner.git

&#x20;   cd vuln-scanner

&#x20;   python -m venv venv

&#x20;   venv\\Scripts\\activate

&#x20;   pip install -r requirements.txt



On Linux/macOS use `source venv/bin/activate` instead of `venv\\Scripts\\activate`.



\## Usage



&#x20;   python scanner.py <target>



Example:



&#x20;   python scanner.py scanme.nmap.org



\## Sample output



&#x20;   Scanning scanme.nmap.org (45.33.32.156)



&#x20;   == Open ports ==

&#x20;   \[OPEN] 22/tcp  SSH  ->  SSH-2.0-OpenSSH\_6.6.1p1 Ubuntu-2ubuntu2.13

&#x20;   \[OPEN] 80/tcp  HTTP  ->  Server: Apache/2.4.7 (Ubuntu)



&#x20;   == Web security headers ==

&#x20;   http://scanme.nmap.org:80/

&#x20;      Status: 200

&#x20;      \[MISSING] Content-Security-Policy  (Helps prevent XSS)

&#x20;      \[MISSING] X-Frame-Options  (Helps prevent clickjacking)

&#x20;      \[MISSING] X-Content-Type-Options  (Prevents MIME sniffing)

&#x20;      \[MISSING] Referrer-Policy  (Controls referrer information leakage)

&#x20;      \[MISSING] Permissions-Policy  (Restricts browser features)

&#x20;      \[INFO] Server: Apache/2.4.7 (Ubuntu)  (version disclosure)



The scan found outdated OpenSSH 6.6.1 and Apache 2.4.7 versions. The full JSON result is in \[sample\_report.json](sample\_report.json).



\## Legal disclaimer



Use this tool only on systems you own or have written permission to test. `scanme.nmap.org` is provided by the Nmap project for testing. Unauthorized scanning may be illegal. The author is not responsible for misuse.



\## Tech



Python, socket, requests, concurrent.futures



\## Author



Mandeep (\[Thor-Loki7](https://github.com/Thor-Loki7))

