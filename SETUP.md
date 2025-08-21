# 🛡️ VulneraMind Security Scanner - Complete Setup Guide

This guide will walk you through setting up VulneraMind from scratch, including all dependencies, databases, AI models, and security tools.

## 📋 Table of Contents

1. [System Requirements](#-system-requirements)
2. [Operating System Setup](#-operating-system-setup)
3. [Python Environment Setup](#-python-environment-setup)
4. [Security Tools Installation](#-security-tools-installation)
5. [Database Setup (NVD/CVE Data)](#-database-setup-nvdcve-data)
6. [AI Models Setup (Ollama)](#-ai-models-setup-ollama)
7. [Frontend Setup](#-frontend-setup)
8. [Project Configuration](#-project-configuration)
9. [Verification & Testing](#-verification--testing)
10. [Troubleshooting](#-troubleshooting)

---

## 🖥️ System Requirements

### Minimum Requirements:
- **OS**: Linux (Ubuntu 20.04+), Windows 10/11 with WSL2, or macOS 12+
- **RAM**: 8GB (16GB recommended)
- **Storage**: 10GB free space
- **Python**: 3.10+ (3.12+ recommended)
- **Node.js**: 18+ (for frontend)
- **Internet**: Required for initial setup and data downloads

### Recommended Specifications:
- **RAM**: 16GB+ for large network scans
- **CPU**: 4+ cores for parallel scanning
- **Storage**: SSD for faster database operations

---

## 🐧 Operating System Setup

### Option 1: Linux (Ubuntu/Debian) - **RECOMMENDED**

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install essential development tools
sudo apt install -y build-essential curl wget git vim
```

### Option 2: Windows with WSL2

1. **Enable WSL2:**
   ```powershell
   # Run as Administrator in PowerShell
   wsl --install -d Ubuntu-22.04
   wsl --set-default-version 2
   ```

2. **Restart your computer and open Ubuntu terminal**

3. **Update WSL Ubuntu:**
   ```bash
   sudo apt update && sudo apt upgrade -y
   sudo apt install -y build-essential curl wget git vim
   ```

### Option 3: macOS

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install essential tools
brew install git curl wget
```

---

## 🐍 Python Environment Setup

### 1. Install Python 3.12+

**Linux/WSL:**
```bash
# Install Python 3.12
sudo apt install -y python3.12 python3.12-venv python3.12-dev python3-pip

# Set Python 3.12 as default (optional)
sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1
```

**macOS:**
```bash
brew install python@3.12
```

**Windows (if not using WSL):**
- Download from [python.org](https://www.python.org/downloads/)
- Choose "Add Python to PATH" during installation

### 2. Clone VulneraMind Repository

```bash
# Clone the repository
git clone https://github.com/M-Umair-J/vulneramind.git
cd vulneramind

# Or if you have SSH configured:
# git clone git@github.com:M-Umair-J/vulneramind.git
```

### 3. Create Python Virtual Environment

```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate  # Linux/macOS/WSL
# .venv\Scripts\activate   # Windows Command Prompt

# Upgrade pip
pip install --upgrade pip setuptools wheel
```

### 4. Install Python Dependencies

```bash
# Install all required packages
pip install -r requirements.txt

# Verify installation
pip list
```

---

## 🔧 Security Tools Installation

### 1. Network Scanning Tools

**Linux/WSL:**
```bash
# Install Nmap
sudo apt install -y nmap

# Install Netcat
sudo apt install -y netcat-traditional

# Verify installations
nmap --version
nc -h
```

**macOS:**
```bash
brew install nmap netcat
```

### 2. Exploit Database

**Linux/WSL:**
```bash
# Install ExploitDB
sudo apt install -y exploitdb

# Update exploit database
sudo searchsploit -u

# Generate JSON database for VulneraMind (REQUIRED)
searchsploit --json > exploitdb.json

# Move to project root if not already there
mv exploitdb.json /path/to/vulneramind/

# Verify installation
searchsploit --help
ls -la exploitdb.json  # Should show a large JSON file
```

**Alternative Method (if searchsploit --json doesn't work):**
```bash
# Download pre-generated ExploitDB JSON
curl -o exploitdb.json https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv
# Note: You may need to convert CSV to JSON format or find an alternative source

# Or create from ExploitDB repository
git clone https://gitlab.com/exploit-database/exploitdb.git /tmp/exploitdb
cd /tmp/exploitdb
# Use provided tools to generate JSON format
```

**macOS:**
```bash
brew install exploitdb
searchsploit --json > exploitdb.json
```

### 3. Metasploit Framework

**Linux/WSL:**
```bash
# Method 1: Official installer (recommended)
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
sudo ./msfinstall

# Method 2: Package manager (Ubuntu/Debian)
sudo apt install -y metasploit-framework

# Initialize Metasploit database
sudo msfdb init

# Start Metasploit and configure RPC for VulneraMind integration
msfconsole

# Inside msfconsole, run this command to enable RPC:
# load msgrpc ServerHost=127.0.0.1 ServerPort=55552 User=msf Pass=abc123 SSL=true

# Verify installation
msfconsole --version
```

**macOS:**
```bash
# Install via Homebrew
brew install --cask metasploit

# Or install manually from official source
```

### 4. Additional Security Tools

```bash
# Install additional useful tools
sudo apt install -y nikto dirb gobuster hydra john hashcat

# For network analysis
sudo apt install -y wireshark tcpdump

# For web application testing
sudo apt install -y sqlmap burpsuite
```

---

## 🗄️ Database Setup (NVD/CVE Data)

### 1. Download NVD Data Files

```bash
# Navigate to data directory
cd backend/core/data

# Download NVD CVE feeds (this will take several minutes)
wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2023.json.gz
wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.gz
wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2025.json.gz
wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz
wget https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz

# Download CPE dictionary
wget https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz

# Extract files
gunzip *.gz

# Rename files to match expected format
mv nvdcve-1.1-2023.json nvdcve-2.0-2023.json
mv nvdcve-1.1-2024.json nvdcve-2.0-2024.json
mv nvdcve-1.1-2025.json nvdcve-2.0-2025.json
mv nvdcve-1.1-modified.json nvdcve-2.0-modified.json
mv nvdcve-1.1-recent.json nvdcve-2.0-recent.json

# Return to project root
cd ../../../
```

### 2. Import Data into SQLite Database

```bash
# Activate virtual environment if not already active
source .venv/bin/activate

# Import NVD data (this takes 5-10 minutes)
python backend/core/scanner/import_nvd_data.py --years 2023,2024,2025

# Expected output:
# ✅ CPE dictionary imported in X.X seconds
# ✅ CVE data imported in X.X seconds
# 📊 Database Statistics:
#   - CPEs: 600,000+
#   - CVEs: 70,000+
#   - CPE-CVE matches: 1,000,000+
```

### 3. Verify Database

```bash
# Check if database was created
ls -la backend/core/data/nvd.db

# Test database query
python -c "
from backend.core.scanner.sqlite_data_loader import get_sqlite_loader
loader = get_sqlite_loader()
stats = loader.get_database_stats()
print(f'CVEs: {stats[\"cve_count\"]:,}')
print(f'CPEs: {stats[\"cpe_count\"]:,}')
"
```

---

## 🤖 AI Models Setup (Ollama)

### 1. Install Ollama

**Linux/WSL:**
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Verify installation
ollama --version
```

**macOS:**
```bash
# Download and install from https://ollama.ai/download
# Or via Homebrew
brew install ollama
```

**Windows:**
- Download installer from [ollama.ai](https://ollama.ai/download)
- Run the installer

### 2. Download AI Models

```bash
# Pull recommended model for security analysis
ollama pull llama3.1

# Alternative models (choose based on your hardware):
# ollama pull llama3.1:8b      # 8B parameters (4GB+ RAM)
# ollama pull llama3.1:70b     # 70B parameters (64GB+ RAM)
# ollama pull codellama        # Code-focused model
# ollama pull mistral          # Lightweight alternative

# List installed models
ollama list
```

### 3. Test AI Integration

```bash
# Test Ollama API
curl http://localhost:11434/api/generate -d '{
  "model": "llama3.1",
  "prompt": "What is a CVE vulnerability?",
  "stream": false
}'

# Test Python integration
python -c "
import ollama
response = ollama.chat(model='llama3.1', messages=[
  {'role': 'user', 'content': 'Explain SQL injection vulnerability'}
])
print(response['message']['content'])
"
```

---

## 🌐 Frontend Setup

### 1. Install Node.js

**Linux/WSL:**
```bash
# Install Node.js 20 LTS
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Verify installation
node --version
npm --version
```

**macOS:**
```bash
brew install node@20
```

**Windows:**
- Download from [nodejs.org](https://nodejs.org/)

### 2. Setup Frontend

```bash
# Navigate to frontend directory
cd vuln-scan-frontend

# Install dependencies
npm install

# Build production version
npm run build

# Test development server (optional)
npm run dev

# Return to project root
cd ..
```

---

## ⚙️ Project Configuration

### 1. Environment Configuration

```bash
# Create environment configuration (optional)
cat > .env << EOF
# API Configuration
API_HOST=localhost
API_PORT=8000

# AI Configuration
OLLAMA_MODEL=llama3.1
OLLAMA_HOST=localhost:11434

# Database Configuration
NVD_DB_PATH=backend/core/data/nvd.db

# Scanning Configuration
DEFAULT_TIMEOUT=5
MAX_CONCURRENT_SCANS=10
EOF
```

### 2. Create Launch Scripts

```bash
# Create backend launch script
cat > start_backend.sh << 'EOF'
#!/bin/bash
echo "🚀 Starting VulneraMind Backend..."
source .venv/bin/activate
cd backend/core
python api_server.py
EOF

# Create frontend launch script
cat > start_frontend.sh << 'EOF'
#!/bin/bash
echo "🌐 Starting VulneraMind Frontend..."
cd vuln-scan-frontend
npm run dev
EOF

# Make scripts executable
chmod +x start_backend.sh start_frontend.sh
```

### 3. Windows Launch Scripts (if not using WSL)

```batch
# Create start_backend.bat
echo @echo off > start_backend.bat
echo echo 🚀 Starting VulneraMind Backend... >> start_backend.bat
echo .venv\Scripts\activate >> start_backend.bat
echo cd backend\core >> start_backend.bat
echo python api_server.py >> start_backend.bat

# Create start_frontend.bat
echo @echo off > start_frontend.bat
echo echo 🌐 Starting VulneraMind Frontend... >> start_frontend.bat
echo cd vuln-scan-frontend >> start_frontend.bat
echo npm run dev >> start_frontend.bat
```

---

## ✅ Verification & Testing

### 1. Test Backend

```bash
# Activate environment
source .venv/bin/activate

# Start backend server
cd backend/core
python api_server.py

# In another terminal, test API
curl http://localhost:8000/health
curl -X POST http://localhost:8000/discover-hosts \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1"}'
```

### 2. Test Frontend

```bash
# Start frontend (in new terminal)
cd vuln-scan-frontend
npm run dev

# Open browser to http://localhost:3000
```

### 3. Test Complete Workflow

1. **Open VulneraMind in browser**: http://localhost:3000
2. **Enter target**: Try `scanme.nmap.org` or your local IP
3. **Run scan**: Click "Start Assessment"
4. **Find exploits**: Click "Find Exploits" after scan completes
5. **AI analysis**: Click "AI Analysis" for recommendations
6. **Generate report**: Click "Generate Report" for PDF/Markdown output

### 4. Test Security Tools

```bash
# Test Nmap
nmap -sV scanme.nmap.org

# Test ExploitDB
searchsploit apache 2.4

# Verify ExploitDB JSON file (CRITICAL)
ls -la exploitdb.json
python -c "
import json
with open('exploitdb.json', 'r') as f:
    data = json.load(f)
    print(f'Loaded {len(data.get(\"RESULTS_EXPLOIT\", []))} exploits')
"

# Test Metasploit
msfconsole -q -x "search apache; exit"

# Test AI model
ollama run llama3.1 "Explain cross-site scripting (XSS)"
```

---

## 🐛 Troubleshooting

### Common Issues and Solutions

#### 1. Python Import Errors
```bash
# Error: ModuleNotFoundError
# Solution: Ensure virtual environment is activated
source .venv/bin/activate
pip install -r requirements.txt
```

#### 2. Database Import Fails
```bash
# Error: Missing NVD files
# Solution: Re-download NVD data
cd backend/core/data
rm -f *.json *.xml
# Re-run download commands from Database Setup section
```

#### 3. Missing ExploitDB JSON File
```bash
# Error: ExploitDB JSON file not found
# Solution: Generate exploitdb.json file
searchsploit --json > exploitdb.json

# Verify file was created and contains data
ls -la exploitdb.json
head -20 exploitdb.json
```

#### 3. Ollama Connection Issues
```bash
# Error: Connection refused to Ollama
# Solution: Start Ollama service
ollama serve &
sleep 5
ollama pull llama3.1
```

#### 4. Permission Denied for Nmap
```bash
# Error: Permission denied for raw sockets
# Solution: Run with sudo or use TCP connect scans
sudo nmap -sS target  # SYN scan (requires root)
nmap -sT target       # TCP connect scan (no root needed)
```

#### 5. Frontend Build Errors
```bash
# Error: Node modules issues
# Solution: Clear cache and reinstall
cd vuln-scan-frontend
rm -rf node_modules package-lock.json
npm install
npm run build
```

#### 6. Metasploit Database Issues
```bash
# Error: Database not initialized
# Solution: Reinitialize Metasploit database
sudo msfdb delete
sudo msfdb init
sudo msfdb start
```

#### 7. WSL Network Issues
```bash
# Error: Cannot access localhost from Windows
# Solution: Use WSL IP address
# Find WSL IP: hostname -I
# Access from Windows: http://WSL_IP:8000
```

### Performance Optimization

#### 1. Faster Database Queries
```bash
# Optimize SQLite database
sqlite3 backend/core/data/nvd.db "VACUUM; ANALYZE;"
```

#### 2. Increase Scan Performance
```bash
# Use faster ping method (optional)
pip install pythonping
# Edit backend/core/scanner/host_discovery.py to enable pythonping
```

#### 3. AI Model Performance
```bash
# Use smaller model for faster responses
ollama pull llama3.1:8b

# Or use quantized model
ollama pull llama3.1:q4_0
```

---

## 🎯 Next Steps

After successful setup:

1. **Read Documentation**: Check `INSTRUCTIONS_AND_CURRENT_PROGRESS.md`
2. **Explore Features**: Try different scan types and AI analysis
3. **Customize Configuration**: Modify settings for your environment
4. **Add Custom Exploits**: Extend the exploit database
5. **Contribute**: Report issues or contribute improvements

---

## 🔐 Security Notes

- **Run in isolated environment**: Use VMs or containers for testing
- **Legal compliance**: Only scan systems you own or have permission to test
- **Keep tools updated**: Regularly update NVD data, exploits, and tools
- **Monitor resource usage**: Large scans can consume significant resources

---

## 📞 Support

- **Issues**: Create issues on GitHub repository
- **Discussions**: Use GitHub Discussions for questions
- **Documentation**: Check project wiki and README files
- **Updates**: Watch repository for latest updates

---

**🛡️ Happy Security Testing with VulneraMind!**
