![Nmap](https://miro.medium.com/v2/resize:fit:828/format:webp/1*Jh3Cz8QbptlnFLtvDTkhQA.png)

## GitHub ID: [CybVulnHunter](https://github.com/CybVulnHunter)

In this lab, I used **Nmap**, a powerful network scanning tool, to perform various types of scans and gather detailed information about the target system.  
The goal was to identify open ports, detect services, and understand the system's exposure to potential vulnerabilities.  
I practiced using different scan types, including ping scans, port scans, and script-based scans.  
This helped improve my skills in network enumeration and security assessment.  
The lab focused on real-world scenarios where scanning is essential for penetration testing and vulnerability analysis.


## 🧰 Nmap Command 

| Command                                | Example                                | Description                                      |
|----------------------------------------|----------------------------------------|--------------------------------------------------|
| `nmap <target>`                        | `nmap 192.168.1.1`                     | Basic scan of a target                          |
| `nmap <target1> <target2>`             | `nmap 192.168.1.1 192.168.1.2`         | Scan multiple targets                           |
| `nmap 192.168.1.1-50`                  | `nmap 192.168.1.1-50`                  | Scan a range of IPs                             |
| `nmap 192.168.1.0/24`                  | `nmap 192.168.1.0/24`                  | Scan an entire subnet                           |
| `nmap -p 22,80,443 <target>`           | `nmap -p 22,80,443 192.168.1.1`        | Scan specific ports                             |
| `nmap -p- <target>`                    | `nmap -p- 192.168.1.1`                 | Scan all ports                                  |
| `nmap -sV <target>`                    | `nmap -sV 192.168.1.1`                 | Service version detection                       |
| `nmap -O <target>`                     | `nmap -O 192.168.1.1`                  | Operating system detection                      |
| `nmap -sT <target>`                    | `nmap -sT 192.168.1.1`                 | TCP connect scan (full connection)              |
| `nmap -sS <target>`                    | `nmap -sS 192.168.1.1`                 | SYN scan (stealth)                              |
| `nmap -sU <target>`                    | `nmap -sU 192.168.1.1`                 | UDP scan                                        |
| `nmap -A <target>`                     | `nmap -A 192.168.1.1`                  | Aggressive scan (version, OS, scripts)          |
| `nmap -p <port> -sV <target>`          | `nmap -p 80 -sV 192.168.1.1`           | Version detection for a specific port           |
| `nmap -Pn <target>`                    | `nmap -Pn 192.168.1.1`                 | Disable host discovery (ping)                   |
| `nmap -sL <target>`                    | `nmap -sL 192.168.1.0/24`              | List targets without scanning                   |
| `nmap -sn <target>`                    | `nmap -sn 192.168.1.0/24`              | Ping scan to determine if hosts are alive       |
| `nmap -v <target>`                     | `nmap -v 192.168.1.1`                  | Verbose mode (more details)                     |
| `nmap -vv <target>`                    | `nmap -vv 192.168.1.1`                 | Very verbose mode                               |
-----

## 🧾 Nmap Advanced Usage & Output Options

| Command                                      | Example                                          | Description                                      |
|----------------------------------------------|--------------------------------------------------|--------------------------------------------------|
| `nmap -oN output.txt <target>`              | `nmap -oN output.txt 192.168.1.1`                | Save output in normal format                     |
| `nmap -oX output.xml <target>`              | `nmap -oX output.xml 192.168.1.1`                | Save output in XML format                        |
| `nmap -oG output.gnmap <target>`            | `nmap -oG output.gnmap 192.168.1.1`              | Save output in grepable format                   |
| `nmap --script <script> <target>`           | `nmap --script http-enum 192.168.1.1`            | Run specific scripts                             |
| `nmap -sP <target>`                         | `nmap -sP 192.168.1.0/24`                        | Ping scan for determining if hosts are up        |
| `nmap --top-ports <number> <target>`        | `nmap --top-ports 20 192.168.1.1`                | Scan the most common ports                       |
| `nmap -p <port> --open <target>`            | `nmap -p 80 --open 192.168.1.1`                  | Show only open ports                             |
| `nmap --max-retries <num> <target>`         | `nmap --max-retries 2 192.168.1.1`               | Set the maximum number of retries                |
| `nmap --min-rate <rate> <target>`           | `nmap --min-rate 100 192.168.1.1`                | Set minimum packet rate per second               |
| `nmap -p 1-1000 <target>`                   | `nmap -p 1-1000 192.168.1.1`                     | Scan the first 1000 ports                        |
| `nmap --scan-delay <time> <target>`         | `nmap --scan-delay 1s 192.168.1.1`               | Set wait time between packets                    |
| `nmap -sT -p 80 <target>`                   | `nmap -sT -p 80 192.168.1.1`                     | TCP connect scan for a specific port             |
| `nmap --script vuln <target>`               | `nmap --script vuln 192.168.1.1`                 | Run vulnerability detection scripts              |
| `nmap -sR <target>`                         | `nmap -sR 192.168.1.1`                           | Scan ports recording responses                   |
| `nmap -6 <target>`                          | `nmap -6 2001:db8::1`                            | IPv6 scanning                                    |
| `nmap -T4 <target>`                         | `nmap -T4 192.168.1.1`                           | Adjust scan speed                                |
| `nmap --version-all <target>`               | `nmap --version-all 192.168.1.1`                 | Detailed version detection                       |
| `nmap --script http-* <target>`             | `nmap --script=http-* 192.168.1.1`               | Run specific HTTP scripts                        |
| `nmap --source-port <port> <target>`        | `nmap --source-port 53 192.168.1.1`              | Scan using a specific source port                |
| `nmap --data-length <length> <target>`      | `nmap --data-length 50 192.168.1.1`              | Send packets with custom data length             |

-----
## 🧾 Nmap Extended Command Cheatsheet

| Command | Example | Description |
|--------|---------|-------------|
| `nmap --badsum <target>` | `nmap --badsum 192.168.1.1` | Send packets with incorrect checksum |
| `nmap --script-args <args> <target>` | `nmap --script=http-brute --script-args user=admin,pass=pass 192.168.1.1` | Pass arguments to scripts |
| `nmap --script-timeout <time> <target>` | `nmap --script-timeout 30s 192.168.1.1` | Set timeout for scripts |
| `nmap --datagram-length <length> <target>` | `nmap --datagram-length 1500 192.168.1.1` | Adjust datagram length |
| `nmap -sV --script=default <target>` | `nmap -sV --script=default 192.168.1.1` | Run Nmap default scripts |
| `nmap --traceroute <target>` | `nmap --traceroute 192.168.1.1` | Perform a traceroute to determine the route |
| `nmap -sA <target>` | `nmap -sA 192.168.1.1` | TCP port scan analysis flags |
| `nmap --packet-trace <target>` | `nmap --packet-trace 192.168.1.1` | Show details of packets sent and received |
| `nmap -p 0-65535 <target>` | `nmap -p 0-65535 192.168.1.1` | Scan all ports |
| `nmap -p 1-1000 --open <target>` | `nmap -p 1-1000 --open 192.168.1.1` | Scan first 1000 ports that are open |
| `nmap -sS -p <port> <target>` | `nmap -sS -p 80 192.168.1.1` | SYN scan for a specific port |
| `nmap -sC <target>` | `nmap -sC 192.168.1.1` | Run default category scripts |
| `nmap -oA <basename> <target>` | `nmap -oA output 192.168.1.1` | Save output in all formats |
| `nmap --script http-methods <target>` | `nmap --script http-methods 192.168.1.1` | Detect supported HTTP methods |
| `nmap -sV --version-intensity <level> <target>` | `nmap -sV --version-intensity 5 192.168.1.1` | Adjust version detection intensity |
| `nmap --top-ports 100 <target>` | `nmap --top-ports 100 192.168.1.1` | Scan the top 100 most common ports |
| `nmap -p <port> --script <script> <target>` | `nmap -p 80 --script http-vuln-cve2014-3704 192.168.1.1` | Run a specific script on a specific port |
| `nmap -sS -p 443 <target>` | `nmap -sS -p 443 192.168.1.1` | Stealth scan on port 443 (HTTPS) |

---

## 🔍 Common NSE Scripts & Special Scans

| Command | Description | Example |
|---------|-------------|---------|
| `nmap -p 80,443 --script ssl-enum-ciphers <target>` | Check SSL/TLS ciphers on web servers | `nmap -p 80,443 --script ssl-enum-ciphers 192.168.1.1` |
| `nmap --script http-vuln-cve2006-3392 <target>` | Check for CVE-2006-3392 vulnerability | `nmap --script http-vuln-cve2006-3392 192.168.1.1` |
| `nmap --script ftp-anon <target>` | Check for anonymous FTP login | `nmap --script ftp-anon 192.168.1.1` |
| `nmap --script smb-vuln-* <target>` | Check for SMB vulnerabilities | `nmap --script smb-vuln-* 192.168.1.1` |
| `nmap --script telnet-encryption <target>` | Check for telnet encryption | `nmap --script telnet-encryption 192.168.1.1` |
| `nmap -sC --script-updatedb` | Update the script database | `nmap -sC --script-updatedb 192.168.1.1` |
| `nmap --script http-sql-injection <target>` | Check for SQL injection vulnerabilities | `nmap --script http-sql-injection 192.168.1.1` |
| `nmap --script http-shellshock <target>` | Check for Shellshock vulnerability | `nmap --script http-shellshock 192.168.1.1` |
| `nmap --script http-stored-xss <target>` | Check for stored XSS vulnerabilities | `nmap --script http-stored-xss 192.168.1.1` |
| `nmap --script http-userdir-enum <target>` | Enumerate user directories on HTTP servers | `nmap --script http-userdir-enum 192.168.1.1` |
| `nmap --script http-vuln-cve2017-5638 <target>` | Check for CVE-2017-5638 vulnerability | `nmap --script http-vuln-cve2017-5638 192.168.1.1` |
| `nmap --script mysql-empty-password <target>` | Check for MySQL empty password vulnerability | `nmap --script mysql-empty-password 192.168.1.1` |
| `nmap --script ssl-cert <target>` | Get SSL certificate details | `nmap --script ssl-cert 192.168.1.1` |
| `nmap --script ssh2-enum-algos <target>` | Enumerate SSH2 algorithms | `nmap --script ssh2-enum-algos 192.168.1.1` |
| `nmap -sP -n <target>` | Disable DNS resolution during ping scan | `nmap -sP -n 192.168.1.0/24` |
| `nmap -sL -n <target>` | List scan without DNS resolution | `nmap -sL -n 192.168.1.0/24` |
| `nmap --script http-vuln-cve2014-3704 <target>` | Check for CVE-2014-3704 vulnerability | `nmap --script http-vuln-cve2014-3704 192.168.1.1` |

------

## 🧩 Nmap HTTP & CVE Script Usage Cheat Sheet

| Command | Description | Example |
|--------|-------------|---------|
| `nmap -sP 192.168.1.0/24` | Ping scan for an entire subnet | `nmap -sP 192.168.1.0/24` |
| `nmap --script http-sitemap-generator <target>` | Generate a sitemap for the web application | `nmap --script http-sitemap-generator 192.168.1.1` |
| `nmap -n -sS 192.168.1.1` | Stealth scan without DNS resolution | `nmap -n -sS 192.168.1.1` |
| `nmap --script http-vuln-cve2017-5638 <target>` | Check for vulnerability in Apache Struts | `nmap --script http-vuln-cve2017-5638 192.168.1.1` |
| `nmap --script http-enum <target>` | Enumerate directories and files on HTTP servers | `nmap --script http-enum 192.168.1.1` |
| `nmap --script dns-brute <target>` | Perform DNS brute-forcing | `nmap --script dns-brute 192.168.1.1` |
| `nmap --script http-csrf <target>` | Check for Cross-Site Request Forgery vulnerabilities | `nmap --script http-csrf 192.168.1.1` |
| `nmap --script http-vuln-cve2018-11776 <target>` | Check for CVE-2018-11776 vulnerability | `nmap --script http-vuln-cve2018-11776 192.168.1.1` |
| `nmap --script http-vuln-cve2015-1635 <target>` | Check for CVE-2015-1635 vulnerability | `nmap --script http-vuln-cve2015-1635 192.168.1.1` |
| `nmap --script http-waf-detect <target>` | Detect Web Application Firewalls | `nmap --script http-waf-detect 192.168.1.1` |
| `nmap --script http-headers <target>` | Get HTTP headers from a web server | `nmap --script http-headers 192.168.1.1` |
| `nmap -sS -sV -p 80,443 <target>` | SYN scan with service version detection on specific ports | `nmap -sS -sV -p 80,443 192.168.1.1` |
| `nmap -p- --script http-title <target>` | Scan all ports and get HTTP titles | `nmap -p- --script http-title 192.168.1.1` |
| `nmap --script http-robots.txt <target>` | Retrieve and analyze the robots.txt file | `nmap --script http-robots.txt 192.168.1.1` |
| `nmap --script http-dos <target>` | Test for Denial of Service vulnerabilities | `nmap --script http-dos 192.168.1.1` |
| `nmap --script dns-cache-snoop <target>` | Check DNS cache snooping vulnerabilities | `nmap --script dns-cache-snoop 192.168.1.1` |
| `nmap --script http-sql-injection <target>` | Check for SQL injection vulnerabilities | `nmap --script http-sql-injection 192.168.1.1` |
| `nmap --script http-vuln-cve2017-10271 <target>` | Check for CVE-2017-10271 vulnerability | `nmap --script http-vuln-cve2017-10271 192.168.1.1` |
| `nmap --script http-vuln-cve2017-1001000 <target>` | Check for CVE-2017-1001000 vulnerability | `nmap --script http-vuln-cve2017-1001000 192.168.1.1` |
| `nmap --script http-vuln-cve2018-14040 <target>` | Check for CVE-2018-14040 vulnerability | `nmap --script http-vuln-cve2018-14040 192.168.1.1` |
| `nmap --script http-vuln-cve2018-11235 <target>` | Check for CVE-2018-11235 vulnerability | `nmap --script http-vuln-cve2018-11235 192.168.1.1` |
| `nmap --script http-vuln-cve2018-11071 <target>` | Check for CVE-2018-11071 vulnerability | `nmap --script http-vuln-cve2018-11071 192.168.1.1` |
| `nmap --script http-vuln-cve2018-1335 <target>` | Check for CVE-2018-1335 vulnerability | `nmap --script http-vuln-cve2018-1335 192.168.1.1` |
| `nmap --script http-vuln-cve2018-1361 <target>` | Check for CVE-2018-1361 vulnerability | `nmap --script http-vuln-cve2018-1361 192.168.1.1` |
| `nmap --script http-vuln-cve2018-7321 <target>` | Check for CVE-2018-7321 vulnerability | `nmap --script http-vuln-cve2018-7321 192.168.1.1` |
